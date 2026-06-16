import math
import os
import time
from collections import Counter
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pygost import gost3410, gost34112012256
import redis.asyncio as aioredis
from typing import Optional

REDIS_HOST = os.getenv("REDIS_HOST", "192.168.32.122")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

redis_client = aioredis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True
)
app = FastAPI(title="Risk Evaluation Engine", version="1.0.0")

@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "risk-engine-pdp"}

class ContextData(BaseModel):
    user_id: str
    fingerprint_hash: str
    fingerprint_raw: str
    ip_address: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    location_source: str
    timestamp: int

class VerifyPayload(BaseModel):
    session_id: str
    nonce: str
    signature_hex: str
    pub_key_hex: str

def calculate_shannon_entropy(data_string: str) -> float:
    if not data_string:
        return 0.0
    probabilities = [n_x / len(data_string) for x, n_x in Counter(data_string).items()]
    entropy = -sum(p * math.log2(p) for p in probabilities)
    return entropy

def haversine_distance(lat1, lon1, lat2, lon2):
    R = 6371
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    return 2 * R * math.asin(math.sqrt(a))


@app.post("/api/v1/risk/evaluate")
async def evaluate_risk(context: ContextData):
    risk_score = 0
    
    entropy = calculate_shannon_entropy(context.fingerprint_raw)
    if entropy < 3.5:
        risk_score += 40
        
    # Гео-фактор: учитываем только при наличии валидных координат
    if context.location_source == 'UNKNOWN' or context.latitude is None:
        # Геолокация недоступна - повышаем риск
        risk_score += 25
    elif context.location_source == 'IP_FALLBACK':
        risk_score += 15

    # Impossible Travel: пропускаем при отсутствии координат
    # NB: эталонная точка захардкожена в прототипе; в боевой системе
    # должна извлекаться из БД истории входов user_id
    if context.latitude is not None and context.longitude is not None:
        last_lat, last_lon = 55.7558, 37.6173
        last_time = (int(time.time()) * 1000) - 3600000

        distance = haversine_distance(
            last_lat, last_lon,
            context.latitude, context.longitude
        )
        time_diff_hours = (context.timestamp - last_time) / 3600000.0

        if time_diff_hours > 0:
            speed = distance / time_diff_hours
            if speed > 900:
                risk_score = 100
        
    action = "ALLOW"
    if risk_score >= 70:
        action = "HIGH_RISK_QR"
    elif risk_score >= 30:
        action = "OFFLINE_FALLBACK"
        
    return {
        "risk_score": min(risk_score, 100), 
        "action": action, 
        "entropy": round(entropy, 2)
    }

@app.post("/api/v1/risk/verify-gost")
async def verify_gost_signature(payload: VerifyPayload):
    redis_key = f"nonce:{payload.session_id}"
    stored_nonce = await redis_client.get(redis_key)

    if stored_nonce is None:
        raise HTTPException(
            status_code=410,
            detail="Сессия истекла или не существует (защита от replay)"
        )

    if stored_nonce != payload.nonce:
        raise HTTPException(
            status_code=400,
            detail="Несоответствие криптографического вызова"
        )

    try:
        curve = gost3410.CURVES["id-tc26-gost-3410-2012-256-paramSetA"]
        pub_key = gost3410.pub_unmarshal(bytes.fromhex(payload.pub_key_hex))
        signature = bytes.fromhex(payload.signature_hex)

        data_to_sign = (payload.nonce + payload.session_id).encode('utf-8')
        digest = gost34112012256.new(data_to_sign).digest()

        is_valid = gost3410.verify(curve, pub_key, digest, signature)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Математически некорректный ключ или подпись"
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Внутренняя ошибка крипто-модуля"
        )

    if not is_valid:
        raise HTTPException(
            status_code=401,
            detail="Криптографическая подпись недействительна"
        )

    await redis_client.delete(redis_key)

    return {
        "status": "success",
        "verified": True,
        "session_id": payload.session_id
    }