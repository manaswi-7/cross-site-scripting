import os
import joblib
import streamlit as st

MODEL_PATH = os.path.join("models", "xss_detector.joblib")

st.set_page_config(page_title="XSS Detection System", page_icon="🛡️")

st.title("🛡️ XSS Attack Detection System")
st.write("Enter HTML/JavaScript text and the trained ML model will classify it as SAFE or XSS ATTACK.")

if not os.path.exists(MODEL_PATH):
    st.error("Model not found. Run: python train.py")
    st.stop()

model = joblib.load(MODEL_PATH)

text = st.text_area(
    "Enter text to check",
    placeholder="Example: <script>alert('XSS')</script>",
    height=150
)

if st.button("Detect XSS"):
    if not text.strip():
        st.warning("Please enter some text.")
    else:
        prediction = model.predict([text])[0]
        probability = model.predict_proba([text])[0][1]

        if prediction == 1:
            st.error(f"🚨 XSS ATTACK DETECTED")
        else:
            st.success("✅ SAFE INPUT")

        st.write(f"Model XSS probability: {probability:.2%}")
