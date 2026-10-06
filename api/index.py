import hashlib
import json
import os
import re
from http.server import BaseHTTPRequestHandler

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "models",
    "xss_detector.joblib",
)

_model = None

HTML = """<<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XSS Attack Detection</title>
<meta name="description" content="Machine-learning based XSS attack detection with SHA-256 cryptographic fingerprinting.">
<style>
*{box-sizing:border-box}body{font-family:Arial,sans-serif;background:#f4f7fb;margin:0;padding:40px;color:#172033}
.card{max-width:760px;margin:auto;background:#fff;padding:32px;border-radius:18px;box-shadow:0 8px 30px #0001}
h1{margin:0 0 8px}.sub{color:#667085}textarea{width:100%;min-height:150px;padding:14px;border:1px solid #ccd3df;border-radius:10px;font-size:16px;margin:18px 0}
button{background:#172033;color:#fff;border:0;padding:12px 22px;border-radius:9px;font-size:16px;cursor:pointer}
button:disabled{opacity:.6;cursor:wait}.result{margin-top:22px;padding:18px;border-radius:10px;font-weight:bold}
.safe{background:#e8f7ed;color:#176b36}.xss{background:#fdecec;color:#b42318}
.examples{margin-top:25px}.example{background:#f7f8fa;padding:10px;border-radius:7px;margin:8px 0;cursor:pointer}
.meta{margin-top:8px;font-size:13px;font-weight:normal;opacity:.8;word-break:break-all}
</style>
</head>
<body>
<div class="card">
<h1>🛡️ XSS Attack Detection</h1>
<p class="sub">ML-based XSS detection with SHA-256 cryptographic fingerprinting.</p>
<textarea id="text" placeholder="Enter HTML or JavaScript text here..."></textarea>
<button id="btn" onclick="detect()">Detect XSS</button>
<div style="margin-top:18px;padding:16px;background:#f7f8fa;border-radius:10px">
<strong>Step 1: Create trusted reference</strong>
<p style="margin:8px 0;color:#667085;font-size:14px">Enter trusted/original content above, then generate its SHA-256 fingerprint.</p>
<button onclick="generateReference()">Generate Reference Hash</button>
<div id="reference" class="meta" style="margin-top:12px;display:none"></div>
</div>
<div style="margin-top:14px">
<strong>Step 2: Verify current content</strong>
<p style="margin:8px 0;color:#667085;font-size:14px">Edit the input above if needed, then compare it with the saved reference.</p>
<button onclick="verifyHash()">Verify Integrity</button>
</div>
<div id="result" style="display:none"></div>
<div class="examples">
<h3>Try an example</h3>
<div class="example" onclick="useExample(this)">&lt;script&gt;alert('XSS')&lt;/script&gt;</div>
<div class="example" onclick="useExample(this)">&lt;img src=x onerror=alert(1)&gt;</div>
<div class="example" onclick="useExample(this)">Hello, welcome to my website</div>
</div>
</div>
<script>
function useExample(e){document.getElementById('text').value=e.textContent}
async function detect(){
 const s=document.getElementById('text').value.trim();
 const r=document.getElementById('result'),b=document.getElementById('btn');
 if(!s){r.style.display='block';r.className='result xss';r.textContent='Please enter some text.';return}
 b.disabled=true;b.textContent='Checking...';
 try{
  const response=await fetch('/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:s})});
  const data=await response.json();
  if(!response.ok) throw new Error(data.error||'API error');
  const attack=data.result==='XSS ATTACK';
  r.style.display='block';r.className='result '+(attack?'xss':'safe');
  r.innerHTML=(attack?'🚨 XSS ATTACK DETECTED':'✅ SAFE INPUT')+
   ' — Detection confidence: '+(Number(data.xss_probability)*100).toFixed(1)+'%'+
   '<div class="meta">Detector: '+data.detector+'</div>'+
   '<div class="meta">SHA-256: '+data.sha256+'</div>';
 }catch(e){
  r.style.display='block';r.className='result xss';r.textContent='Detection service unavailable. Please try again.';
 }finally{b.disabled=false;b.textContent='Detect XSS'}
}
async function generateReference(){
 const s=document.getElementById('text').value.trim(),ref=document.getElementById('reference');
 if(!s){ref.style.display='block';ref.textContent='Enter trusted/original content first.';return}
 try{
  const response=await fetch('/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'hash',text:s})});
  const data=await response.json();
  if(!response.ok) throw new Error(data.error||'Hash generation error');
  localStorage.setItem('xssReferenceHash',data.sha256);
  ref.style.display='block';
  ref.innerHTML='Reference SHA-256: <span style="font-family:monospace">'+data.sha256+'</span><br><button onclick="copyReference()" style="margin-top:8px">Copy Hash</button>';
 }catch(e){ref.style.display='block';ref.textContent=e.message}
}
function copyReference(){
 const h=localStorage.getItem('xssReferenceHash');
 if(h) navigator.clipboard.writeText(h);
}
async function verifyHash(){
 const s=document.getElementById('text').value.trim(),h=localStorage.getItem('xssReferenceHash'),r=document.getElementById('result');
 if(!s||!h){r.style.display='block';r.className='result xss';r.textContent='Generate a reference hash first, then enter the current content.';return}
 try{
  const response=await fetch('/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'verify',text:s,reference_hash:h})});
  const data=await response.json();
  if(!response.ok) throw new Error(data.error||'Verification error');
  r.style.display='block';r.className='result '+(data.match?'safe':'xss');
  r.innerHTML=(data.match?'✅ INTEGRITY VERIFIED':'⚠️ INPUT MODIFIED')+
   '<div class="meta">Current SHA-256: '+data.sha256+'</div>'+
   '<div class="meta">'+(data.match?'The current input matches the reference hash.':'The current input does not match the reference hash.')+'</div>';
 }catch(e){r.style.display='block';r.className='result xss';r.textContent=e.message}
}
</script>
</body>
</html>"""

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
    patterns = [
        r"<\s*script\b", r"on\w+\s*=", r"javascript\s*:",
        r"<\s*iframe\b", r"<\s*svg\b[^>]*on\w+\s*=",
        r"<\s*img\b[^>]*on\w+\s*=", r"alert\s*\(",
        r"document\.(cookie|location)", r"<\s*body\b[^>]*on\w+\s*="
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

def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def send_json(h, status, data):
    body = json.dumps(data).encode("utf-8")
    h.send_response(status)
    h.send_header("Content-Type","application/json")
    h.send_header("Access-Control-Allow-Origin","*")
    h.send_header("Access-Control-Allow-Methods","GET, POST, OPTIONS")
    h.send_header("Access-Control-Allow-Headers","Content-Type")
    h.end_headers()
    h.wfile.write(body)

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        send_json(self, 200, {"status":"ok"})

    def do_GET(self):
        body = HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Cache-Control","no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            text = str(data.get("text","")).strip()
            if not text:
                send_json(self,400,{"error":"Please enter text."})
                return

            attack, probability, detector = predict(text)
            file_hash = sha256_text(text)
            action = data.get("action", "detect")

            if action == "hash":
                send_json(self,200,{"sha256":file_hash})
                return

            if action == "verify":
                reference_hash = str(data.get("reference_hash","")).strip().lower()
                if not re.fullmatch(r"[0-9a-f]{64}", reference_hash):
                    send_json(self,400,{"error":"Please enter a valid 64-character SHA-256 hash."})
                    return
                send_json(self,200,{
                    "match": file_hash == reference_hash,
                    "sha256": file_hash
                })
                return

            send_json(self,200,{
                "result":"XSS ATTACK" if attack else "SAFE",
                "xss_probability":round(probability,4),
                "detector":detector,
                "sha256":file_hash
            })
        except Exception as e:
            send_json(self,500,{"error":str(e)})
