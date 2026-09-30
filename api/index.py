import json
import os
import re

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "models",
    "xss_detector.joblib",
)

_model = None

def load_model():
    global _model
    if _model is None and os.path.exists(MODEL_PATH):
        try:
            import joblib
            _model = joblib.load(MODEL_PATH)
        except Exception:
            _model = False
    return _model

def fallback_detect(text):
    # Safe fallback keeps the deployed demo available if the optional
    # serialized ML model is not packaged with the deployment.
    patterns = [
        r"<\s*script\b",
        r"on\w+\s*=",
        r"javascript\s*:",
        r"<\s*iframe\b",
        r"<\s*svg\b[^>]*on\w+\s*=",
        r"<\s*img\b[^>]*on\w+\s*=",
        r"alert\s*\(",
        r"document\.(cookie|location)",
        r"<\s*body\b[^>]*on\w+\s*=",
    ]
    score = sum(bool(re.search(p, text, re.IGNORECASE)) for p in patterns)
    return score > 0, min(0.99, 0.60 + score * 0.05) if score else 0.01

def predict(text):
    model = load_model()
    if model:
        prediction = int(model.predict([text])[0])
        probability = float(model.predict_proba([text])[0][1])
        return prediction == 1, probability, "ML model"

    attack, probability = fallback_detect(text)
    return attack, probability, "fallback detector"

def send_json(handler, status, data):
    body = json.dumps(data).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.end_headers()
    handler.wfile.write(body)

from http.server import BaseHTTPRequestHandler

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        send_json(self, 200, {"status": "ok"})

    def do_GET(self):
        send_json(self, 200, {
            "status": "ok",
            "message": "XSS detection API is running"
        })

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body or "{}")
            text = str(data.get("text", "")).strip()

            if not text:
                send_json(self, 400, {"error": "Please enter text."})
                return

            attack, probability, detector = predict(text)
            send_json(self, 200, {
                "result": "XSS ATTACK" if attack else "SAFE",
                "xss_probability": round(probability, 4),
                "detector": detector
            })
        except Exception as e:
            send_json(self, 500, {"error": str(e)})
