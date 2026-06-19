import os

import requests
from flask import Flask, jsonify, render_template, request


app = Flask(__name__)

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:3000")
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "5"))


def _gateway_post(path: str, payload: dict):
    try:
        response = requests.post(
            f"{GATEWAY_URL}{path}",
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.exceptions.RequestException as exc:
        return jsonify({
            "error": "Gateway unavailable",
            "detail": str(exc),
        }), 503

    try:
        body = response.json()
    except ValueError:
        body = {"error": "Gateway returned non-JSON response", "body": response.text}

    return jsonify(body), response.status_code


def _normalize_init_payload(data: dict) -> dict:
    if "clientData" in data:
        return {
            "login": data.get("login", "p.nesterenko"),
            "clientData": data.get("clientData") or {},
        }

    lat = data.get("lat")
    lon = data.get("lon")
    gps = None
    if lat not in (None, "") and lon not in (None, ""):
        try:
            gps = {"lat": float(lat), "lon": float(lon)}
        except (TypeError, ValueError):
            gps = None

    client_data = {
        "screenResolution": data.get("screenResolution", "unknown"),
        "timezone": data.get("timezone", "unknown"),
        "hardwareConcurrency": data.get("hardwareConcurrency", "unknown"),
        "canvasHash": data.get("fingerprint", data.get("canvasHash", "unknown")),
        "gps": gps,
    }

    return {
        "login": data.get("login", "p.nesterenko"),
        "clientData": client_data,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "dashboard-bff"})


@app.route("/api/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    payload = _normalize_init_payload(data)
    return _gateway_post("/api/auth/init", payload)


@app.route("/api/qr-generate", methods=["POST"])
def qr_generate():
    data = request.get_json(silent=True) or {}
    return _gateway_post("/api/auth/qr-generate", data)


@app.route("/api/qr-verify", methods=["POST"])
def qr_verify():
    data = request.get_json(silent=True) or {}
    return _gateway_post("/api/auth/qr-verify", data)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5050")), debug=True)

