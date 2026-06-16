const fastify = require('fastify')({ logger: true });
const crypto = require('crypto');
const geoip = require('geoip-lite');
const axios = require('axios');
const Redis = require('ioredis');

const redis = new Redis({
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: parseInt(process.env.REDIS_PORT || '6379', 10)
});
const RISK_ENGINE_URL = process.env.RISK_ENGINE_URL || 'http://127.0.0.1:8000';

// Регистрация JWT-плагина
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('FATAL: JWT_SECRET не задан или короче 32 символов');
    process.exit(1);
}

fastify.register(require('@fastify/jwt'), {
    secret: JWT_SECRET,
    sign: {
        algorithm: 'HS256',
        expiresIn: '1h'
    }
});

// Вспомогательная функция выдачи токена
function issueToken(login, sessionContext = {}) {
    return fastify.jwt.sign({
        sub: login,
        iat: Math.floor(Date.now() / 1000),
        ...sessionContext
    });
}

function generateBrowserFingerprint(headers, clientData) {
    const rawData = [
        headers['user-agent'] || 'unknown',
        headers['accept-language'] || 'unknown',
        clientData.screenResolution || 'unknown',
        clientData.timezone || 'unknown',
        clientData.hardwareConcurrency || 'unknown',
        clientData.canvasHash || 'unknown'
    ].join('|');
    return crypto.createHash('sha256').update(rawData).digest('hex');
}

function resolveLocation(ip, clientGps) {
    if (clientGps && clientGps.lat && clientGps.lon) {
        return { lat: clientGps.lat, lon: clientGps.lon, source: 'EXACT_GPS' };
    }
    const geo = geoip.lookup(ip);
    if (geo) {
        return { lat: geo.ll[0], lon: geo.ll[1], source: 'IP_FALLBACK' };
    }
    // Геолокация недоступна - помечаем источник как UNKNOWN,
    // ядро PDP должно повысить риск по этому признаку
    return { lat: null, lon: null, source: 'UNKNOWN' };
}

fastify.get('/health', async (request, reply) => {
    return { status: 'ok', service: 'pep-auth-gateway' };
});

// =========================================================================
// Маршрут 1: первичный приём учётных данных, делегирование оценки риска
// =========================================================================
fastify.post('/api/auth/init', async (request, reply) => {
    const { login, clientData } = request.body;
    const ipAddress = request.ip || '127.0.0.1';

    const fingerprint = generateBrowserFingerprint(request.headers, clientData);
    const location = resolveLocation(ipAddress, clientData.gps);

    const contextPayload = {
        user_id: login,
        fingerprint_hash: fingerprint,
        fingerprint_raw: JSON.stringify(clientData),
        ip_address: ipAddress,
        latitude: location.lat,
        longitude: location.lon,
        location_source: location.source,
        timestamp: Date.now()
    };

    try {
        const riskResponse = await axios.post(
            `${RISK_ENGINE_URL}/api/v1/risk/evaluate`,
            contextPayload
        );
        const { risk_score, action, entropy } = riskResponse.data;

        // Сохраняем контекст сессии для последующих шагов
        const sessionId = crypto.randomUUID();
        await redis.setex(
            `session:${sessionId}`,
            300, // TTL=5min для всего сценария аутентификации
            JSON.stringify({ login, action, risk_score, entropy })
        );

        // Для низкорискового сценария выдаём токен сразу
        if (action === 'ALLOW') {
            const token = issueToken(login, { risk_score, method: 'DIRECT' });
            return reply.send({
                status: 'success',
                method: 'DIRECT',
                token,
                risk_score,
                entropy
            });
        }

        return reply.send({
            status: 'evaluated',
            session_id: sessionId,
            action,
            risk_score,
            entropy
        });
    } catch (error) {
        fastify.log.error({ err: error }, "Ошибка обращения к PDP");
        return reply.code(503).send({ error: 'Сервис оценки рисков недоступен' });
    }
});

// =========================================================================
// Маршрут 2: генерация QR-вызова (вызывается, если action === HIGH_RISK_QR)
// =========================================================================
fastify.post('/api/auth/qr-generate', async (request, reply) => {
    const { session_id } = request.body;

    if (!session_id) {
        return reply.code(400).send({ error: 'session_id обязателен' });
    }

    const sessionData = await redis.get(`session:${session_id}`);
    if (!sessionData) {
        return reply.code(410).send({ error: 'Сессия истекла или не существует' });
    }

    const session = JSON.parse(sessionData);
    if (session.action !== 'HIGH_RISK_QR') {
        return reply.code(403).send({
            error: 'QR-аутентификация не требуется для данной сессии'
        });
    }

    const nonce = crypto.randomBytes(16).toString('hex');
    await redis.setex(`nonce:${session_id}`, 60, nonce); // TTL=60s

    return reply.send({
        session_id,
        nonce,
        timestamp: Math.floor(Date.now() / 1000),
        resource: 'Corporate_Core_Network'
    });
});

// =========================================================================
// Маршрут 3: верификация QR-подписи (вызывается мобильным клиентом)
// =========================================================================
fastify.post('/api/auth/qr-verify', async (request, reply) => {
    const { session_id, nonce, signature_hex, pub_key_hex } = request.body;

    if (!session_id || !nonce || !signature_hex || !pub_key_hex) {
        return reply.code(400).send({ error: 'Не все параметры предоставлены' });
    }

    // Делегируем проверку подписи ядру PDP (с проверкой nonce из Redis)
    try {
        const verifyResponse = await axios.post(
            `${RISK_ENGINE_URL}/api/v1/risk/verify-gost`,
            { session_id, nonce, signature_hex, pub_key_hex }
        );

        if (verifyResponse.data.verified) {
            // Извлекаем login из сохранённого контекста сессии
            const sessionData = await redis.get(`session:${session_id}`);
            const session = sessionData ? JSON.parse(sessionData) : {};

            // Очищаем сессию после успешной верификации
            await redis.del(`session:${session_id}`);

            const token = issueToken(session.login || 'unknown', {
                risk_score: session.risk_score,
                method: 'QR_GOST'
            });

            return reply.send({
                status: 'success',
                method: 'QR_GOST',
                session_id,
                token
            });
        }

        return reply.code(401).send({ error: 'Подпись не прошла верификацию' });
    } catch (error) {
        const status = error.response?.status || 500;
        const detail = error.response?.data?.detail || 'Ошибка верификации';
        return reply.code(status).send({ error: detail });
    }
});

fastify.listen({ port: 3000, host: '0.0.0.0' }, (err) => {
    if (err) {
        fastify.log.error(err);
        process.exit(1);
    }
});
