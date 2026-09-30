import json
import os
import joblib
from http.server import BaseHTTPRequestHandler

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "models",
    "xss_detector.joblib",
)

model = joblib.load(MODEL_PATH)

class handler(BaseHTTPRequestHandler):
    def _send(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(200, {"status": "ok"})

    def do_GET(self):
        self._send(200, {
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
                self._send(400, {"error": "Please enter text."})
                return

            prediction = int(model.predict([text])[0])
            probability = float(model.predict_proba([text])[0][1])

            self._send(200, {
                "result": "XSS ATTACK" if prediction == 1 else "SAFE",
                "xss_probability": round(probability, 4)
            })
        except Exception as e:
            self._send(500, {"error": str(e)})
