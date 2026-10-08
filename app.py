import json
import os
import re
import uuid
from datetime import datetime, timezone
from email.utils import parseaddr
from urllib.parse import urlparse
from pathlib import Path

import joblib
import tldextract
from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "nlp_pipeline.joblib"
DATA_FILE = BASE_DIR / "data" / "triage_store.json"

app = Flask(__name__)
_model = None
_model_error = None

URGENT = ["urgent", "immediately", "act now", "within 24 hours", "suspend", "suspended", "final warning", "verify now", "immediate action"]
CREDENTIAL = ["password", "login", "credential", "sign in", "signin", "verify your account", "confirm your account", "one-time password", "otp", "username"]
PAYMENT = ["payment", "invoice", "wire transfer", "bank account", "gift card", "pay now", "refund", "bitcoin", "crypto", "transfer money"]
IMPERSONATION = ["ceo", "manager", "director", "microsoft", "office", "outlook", "google", "amazon", "paypal", "support team", "it helpdesk", "security team", "hr department", "administrator"]
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "xyz", "work", "country", "gq", "tk", "ml", "cf"}
TRUSTED_BRANDS = {"microsoft", "office", "outlook", "google", "gmail", "apple", "amazon", "paypal", "linkedin", "docusign", "github", "bank"}

def load_model():
    global _model, _model_error
    if _model is not None:
        return _model
    if not MODEL_PATH.exists():
        _model_error = "NLP model file was not found."
        return None
    try:
        _model = joblib.load(MODEL_PATH)
        _model_error = None
        return _model
    except Exception as exc:
        _model = None
        _model_error = str(exc)
        return None

def load_store():
    if not DATA_FILE.exists():
        return {"emails": [], "feedback": []}
    try:
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"emails": [], "feedback": []}

def save_store(store):
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(store, indent=2), encoding="utf-8")

def extract_urls(text):
    return [u.rstrip(".,);]}") for u in URL_RE.findall(text or "")]

def looks_like_ip(host):
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def brand_lookalike(domain):
    domain = (domain or "").lower()
    normalized = domain.translate(str.maketrans({"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t"}))
    for brand in TRUSTED_BRANDS:
        if brand in domain and domain not in {brand + ".com", "www." + brand + ".com"}:
            return True
        if brand in normalized and normalized != brand + ".com":
            return True
    return False

def analyze_headers(sender, reply_to, return_path, spf, dkim, dmarc):
    score = 0.0
    signals = []
    sender_addr = parseaddr(sender)[1].lower()
    reply_addr = parseaddr(reply_to)[1].lower()
    return_addr = parseaddr(return_path)[1].lower()
    for name, value, weight in [("SPF", spf, 22), ("DKIM", dkim, 22), ("DMARC", dmarc, 26)]:
        if (value or "").lower() in {"fail", "failed", "softfail", "permerror"}:
            score += weight; signals.append(f"{name} authentication failed")
        elif (value or "").lower() == "pass": signals.append(f"{name} authentication passed")
    sender_domain = sender_addr.split("@",1)[1] if "@" in sender_addr else ""
    if sender_addr and reply_addr:
        reply_domain = reply_addr.split("@",1)[1] if "@" in reply_addr else ""
        if sender_domain and reply_domain and sender_domain != reply_domain:
            score += 25; signals.append("From and Reply-To domains do not match")
    if sender_addr and return_addr:
        return_domain = return_addr.split("@",1)[1] if "@" in return_addr else ""
        if sender_domain and return_domain and sender_domain != return_domain:
            score += 20; signals.append("Sender and Return-Path domains do not match")
    if not sender_addr:
        score += 15; signals.append("Sender address is missing or malformed")
    if not signals: signals.append("No high-risk header mismatch detected")
    return min(score,100), signals, {"spf":str(spf).lower(),"dkim":str(dkim).lower(),"dmarc":str(dmarc).lower()}

def analyze_urls(text):
    urls = extract_urls(text); score = 0.0; signals = []; domains=[]
    for url in urls:
        try:
            parsed=urlparse(url); host=(parsed.hostname or "").lower()
        except Exception: continue
        ext=tldextract.extract(host); registered=ext.registered_domain or host; domains.append(registered)
        if looks_like_ip(host): score+=25; signals.append("URL uses an IP address instead of a domain")
        if len(url)>120: score+=10; signals.append("URL is unusually long")
        if "@" in (parsed.netloc or ""): score+=20; signals.append("URL contains an @ symbol in the authority section")
        if ext.suffix.lower() in SUSPICIOUS_TLDS: score+=18; signals.append(f"URL uses a higher-risk TLD: .{ext.suffix}")
        if "xn--" in host: score+=25; signals.append("URL uses punycode, which can be used for look-alike domains")
        if brand_lookalike(registered): score+=30; signals.append(f"URL resembles a trusted brand domain: {registered}")
        if parsed.scheme.lower() != "https": score+=8; signals.append("URL does not use HTTPS")
        if host.count(".") >= 4: score+=8; signals.append("URL contains an unusually deep subdomain structure")
    if not urls: signals.append("No URLs found in the supplied email")
    elif not signals: signals.append("No strong URL/domain anomaly detected")
    return min(score,100), signals, {"url_count":len(urls),"domains":domains}, urls

def analyze_text(subject, body):
    text=f"{subject}\n{body}".strip(); signals=[]; features={}; model=load_model(); score=50.0
    if model is not None and text:
        try:
            probability=float(model.predict_proba([text])[0][1]); score=probability*100; features["model_probability"]=round(probability,4)
        except Exception as exc:
            features["model_probability"]=None; features["model_error"]=str(exc); signals.append("NLP model could not be executed; using behavioral text signals")
    else:
        features["model_probability"]=None; signals.append("NLP model is unavailable; using behavioral text signals")
        if _model_error: features["model_error"]=_model_error
    for name, terms in [("urgency",URGENT),("credential",CREDENTIAL),("payment",PAYMENT),("impersonation",IMPERSONATION)]:
        hits=[term for term in terms if term in text.lower()]; features[name]=hits
        if hits: score+=min(15,4*len(hits)); signals.append(f"NLP detected {name} language: {', '.join(hits[:4])}")
    if not signals: signals.append("NLP classifier did not find additional behavioral text indicators")
    return min(score,100), signals, features

def calculate_risk(header_score,url_score,nlp_score,header_features,url_features,nlp_features):
    risk=0.30*header_score+0.35*url_score+0.35*nlp_score
    auth_failures=sum(header_features.get(k)=="fail" for k in ("spf","dkim","dmarc"))
    if auth_failures>=3: risk=max(risk,85)
    elif auth_failures>=2: risk=max(risk,70)
    elif auth_failures>=1: risk=max(risk,30)
    indicators=[bool(nlp_features.get("urgency")),bool(nlp_features.get("credential")),bool(nlp_features.get("impersonation")),bool(nlp_features.get("payment")),url_score>=30]
    count=sum(indicators)
    if count>=4: risk=max(risk,80)
    elif count>=3: risk=max(risk,70)
    elif count>=2: risk=max(risk,55)
    risk=round(max(0,min(risk,100)),2); level="CRITICAL" if risk>=70 else "SUSPICIOUS" if risk>=30 else "SAFE"; return risk,level

def uncertainty_review(email,scores,signals):
    return True, "Local uncertainty review: manual verification is recommended for borderline cases."

def run_analysis(data):
    sender=data.get("sender",""); receiver=data.get("receiver",""); subject=data.get("subject",""); body=data.get("body","")
    header_score,header_signals,header_features=analyze_headers(sender,data.get("reply_to",""),data.get("return_path",""),data.get("spf","unknown"),data.get("dkim","unknown"),data.get("dmarc","unknown"))
    url_score,url_signals,url_features,urls=analyze_urls(f"{subject}\n{body}"); nlp_score,nlp_signals,nlp_features=analyze_text(subject,body)
    risk_score,risk_level=calculate_risk(header_score,url_score,nlp_score,header_features,url_features,nlp_features); signals=header_signals+url_signals+nlp_signals
    llm_reviewed=False; llm_reasoning=""
    if 30<=risk_score<70: llm_reviewed,llm_reasoning=uncertainty_review({"sender":sender,"receiver":receiver,"subject":subject,"body":body},(header_score,url_score,nlp_score),signals)
    return {"id":str(uuid.uuid4()),"created_at":datetime.now(timezone.utc).isoformat(),"sender":sender,"receiver":receiver,"subject":subject,"body":body,"header_score":round(header_score,2),"url_score":round(url_score,2),"nlp_score":round(nlp_score,2),"risk_score":risk_score,"risk_level":risk_level,"signals":signals[:20],"llm_reviewed":llm_reviewed,"llm_reasoning":llm_reasoning,"urls":urls,"analyzer_details":{"header":header_features,"url":url_features,"nlp":nlp_features}}

@app.get("/")
def home(): return render_template("index.html")
@app.get("/health")
def health(): return jsonify({"status":"ok","service":"overloaded-phishing-inbox","model_available":MODEL_PATH.exists(),"model_loaded":load_model() is not None})
@app.post("/analyze")
def analyze():
    data=request.get_json(silent=True) or {}
    if not data.get("subject") and not data.get("body"): return jsonify({"error":"Please provide an email subject or body."}),400
    try:
        result=run_analysis(data); store=load_store(); store["emails"].insert(0,result); store["emails"]=store["emails"][:200]; save_store(store); return jsonify(result)
    except Exception as exc: return jsonify({"error":"Email analysis failed.","details":str(exc)}),500
@app.post("/emails/analyze")
def analyze_api(): return analyze()
@app.get("/emails")
def emails(): return jsonify(load_store().get("emails",[])[:100])
@app.delete("/emails/clear")
def clear_emails():
    store=load_store(); store["emails"]=[]; save_store(store); return jsonify({"status":"cleared"})
@app.get("/emails/<email_id>")
def email_detail(email_id):
    result=next((item for item in load_store().get("emails",[]) if item.get("id")==email_id),None)
    if result is None: return jsonify({"error":"Email not found"}),404
    return jsonify(result)
@app.post("/feedback")
def feedback():
    data=request.get_json(silent=True) or {}; store=load_store(); store["feedback"].insert(0,{**data,"created_at":datetime.now(timezone.utc).isoformat()}); save_store(store); return jsonify({"status":"recorded"})
if __name__ == "__main__": app.run(host="127.0.0.1",port=5000,debug=True)
