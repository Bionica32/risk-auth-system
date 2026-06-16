from pygost import gost3410, gost34112012256

def verify_gost_signature(pub_key_hex: str, nonce: str, session_id: str, signature_hex: str) -> bool:
    try:
        curve = gost3410.CURVES["id-tc26-gost-3410-2012-256-paramSetA"]
        pub_key = gost3410.pub_unmarshal(bytes.fromhex(pub_key_hex))
        signature = bytes.fromhex(signature_hex)
        data_to_sign = (nonce + session_id).encode('utf-8')
        digest = gost34112012256.new(data_to_sign).digest()
        return gost3410.verify(curve, pub_key, digest, signature)
    except (ValueError, TypeError, Exception):
        return False

def get_stribog256_hash(data: str) -> str:
    try:
        digest = gost34112012256.new(data.encode('utf-8')).digest()
        return digest.hex()
    except Exception:
        return ""