import os, math, time, requests
from flask import Flask, render_template, request, jsonify
from pygost import gost3410, gost34112012256

app = Flask(__name__)

RISK_ENGINE_URL = "http://127.0.0.1:8000/api/v1/risk/verify-gost"
GATEWAY_URL = "http://127.0.0.1:3000"

TRUSTED = {
    "ip": "192.168.1.5",
    "fp": "fp_bionica_macbook",
    "lat": 55.75,
    "lon": 37.61, 
    "last_time": time.time() - 3600
}

def get_haversine_distance(lat1, lon1, lat2, lon2):
    """Расчет геодезического расстояния (Impossible Travel)"""
    R = 6371  
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2 * R * math.asin(math.sqrt(a))

def calculate_local_risk(data):
    """Логика вычисления риск-балла для отрисовки в UI"""
    score = 0
    reasons = []

    if data['ip'] != TRUSTED['ip']:
        score += 30
        reasons.append("Нетипичный IP (Возможен VPN/Proxy)")

    if data['fingerprint'] != TRUSTED['fp']:
        score += 40
        reasons.append("Новый отпечаток устройства (Fingerprint)")

    dist = get_haversine_distance(TRUSTED['lat'], TRUSTED['lon'], float(data['lat']), float(data['lon']))
    time_diff = (time.time() - TRUSTED['last_time']) / 3600 
    speed = dist / time_diff if time_diff > 0 else 9999

    if speed > 900:
        score = 100
        reasons = [f"Impossible Travel: Скорость {int(speed)} км/ч превышает порог"]
    elif dist > 200:
        score += 20
        reasons.append(f"Значительное смещение локации (+{int(dist)} км)")

    return min(score, 100), reasons

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/verify', methods=['POST'])
def verify():
    data = request.json
    
    score, reasons = calculate_local_risk(data)
    action = "BLOCK" if score >= 70 else "GRANT"

    print("\n📱 Инициализация мобильного эмулятора (pygost)...")
    curve = gost3410.CURVES["id-tc26-gost-3410-2012-256-paramSetA"]
    
    prv_raw = os.urandom(32)
    prv_key = gost3410.prv_unmarshal(prv_raw) 
    pub_key_point = gost3410.public_key(curve, prv_key) 
    pub_key_hex = gost3410.pub_marshal(pub_key_point).hex()

    session_id = f"ses_{int(time.time())}"
    nonce = f"n_{int(time.time())}"

    data_to_sign = (nonce + session_id).encode('utf-8')
    dgst = gost34112012256.new(data_to_sign).digest()
    
    signature = gost3410.sign(curve, prv_key, dgst)
    signature_hex = signature.hex()
    print(f"✍️ Вызов успешно подписан! Подпись: {signature_hex[:16]}...")

    payload = {
        "session_id": session_id,
        "nonce": nonce,
        "signature_hex": signature_hex,
        "pub_key_hex": pub_key_hex,
        "context": {
            "ip_address": data['ip'],
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "device_fingerprint": data['fingerprint'],
            "latitude": float(data['lat']),
            "longitude": float(data['lon']),
            "timestamp": int(time.time()) 
        }
    }

    try:
        print("🌐 Отправка валидного ответа на сервер оценки рисков...")
        resp = requests.post(RISK_ENGINE_URL, json=payload, timeout=2)
        
        print("-" * 50)
        print(f"Статус-код ответа Risk Engine: {resp.status_code}")
        try:
            print(f"Ответ сервера: {resp.json()}")
        except:
            print(f"Ответ сервера: {resp.text}")
        print("-" * 50)
            
        requests.get(GATEWAY_URL, timeout=1)
    except Exception as e:
        print(f"Ошибка сети: {e}")

    return jsonify({
        "risk_score": score,
        "action": action,
        "reasons": reasons
    })

if __name__ == '__main__':
    app.run(port=5050, debug=True)