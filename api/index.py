import json
import os
import joblib

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "models",
    "xss_detector.joblib"
)

model = joblib.load(MODEL_PATH)

def handler(request):
    if request.method == "GET":
        return {
            "status": "ok",
            "message": "XSS detection API is running"
        }

    try:
        body = request.body
        if isinstance(body, bytes):
            body = body.decode("utf-8")

        data = json.loads(body or "{}")
        text = str(data.get("text", "")).strip()

        if not text:
            return {
                "error": "Please enter text."
            }

        prediction = int(model.predict([text])[0])
        probability = float(model.predict_proba([text])[0][1])

        return {
            "result": "XSS ATTACK" if prediction == 1 else "SAFE",
            "xss_probability": round(probability, 4)
        }

    except Exception as e:
        return {
            "error": str(e)
        }
