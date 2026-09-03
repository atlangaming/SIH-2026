import os
import re
import json
from datetime import datetime
from typing import List
import quopri

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from email import message_from_bytes
from email.policy import default

import requests
import whois
import dns.resolver
from groq import Groq

# =============================================================================
# 1. APPLICATION & MIDDLEWARE SETUP
# =============================================================================
app = FastAPI(title="Email Forensics API")

# Enable CORS for local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Groq Client setup (reads GROQ_API_KEY from environment automatically)
# To run: export GROQ_API_KEY="your-key-here"
groq_client = Groq()

# =============================================================================
# 2. WEBSOCKET MANAGER
# =============================================================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, data: dict):
        for connection in self.active_connections:
            await connection.send_json(data)

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # Keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# =============================================================================
# 3. PARSING & EXTRACTION HELPERS
# =============================================================================
import quopri

def extract_clean_body(msg) -> str:
    """Safely extracts plain text or strips HTML from .eml messages."""
    body_text = ""
    html_fallback = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition.lower():
                continue

            payload = part.get_payload(decode=True)
            if not payload:
                continue

            charset = part.get_content_charset() or 'utf-8'
            decoded_text = payload.decode(charset, errors='ignore')

            if content_type == "text/plain" and not body_text:
                body_text = decoded_text
            elif content_type == "text/html" and not html_fallback:
                html_fallback = decoded_text
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or 'utf-8'
            decoded_text = payload.decode(charset, errors='ignore')
            if msg.get_content_type() == "text/html":
                html_fallback = decoded_text
            else:
                body_text = decoded_text

    # If only HTML was present, strip out the tags
    if not body_text and html_fallback:
        body_text = re.sub(r'<[^>]+>', ' ', html_fallback)

    clean_text = " ".join(body_text.split())
    return clean_text[:4000]

# =============================================================================
# 4. ENRICHMENT MODULES (OSINT)
# =============================================================================
def enrich_ip(ip: str) -> dict:
    if not ip:
        return {}
    try:
        # Added lat,lon to fields
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,proxy,hosting,lat,lon", 
            timeout=5
        ).json()
        return {
            "country": resp.get("country", "Unknown"),
            "city": resp.get("city", "Unknown"),
            "isp": resp.get("isp", "Unknown"),
            "is_proxy_or_vpn": resp.get("proxy", False),
            "is_hosting_provider": resp.get("hosting", False),
            "lat": resp.get("lat"),
            "lon": resp.get("lon")
        }
    except Exception:
        return {"error": "IP lookup timeout"}

def domain_intel(domain: str) -> dict:
    if not domain:
        return {}
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        domain_age_days = (datetime.now() - creation_date).days if creation_date else None
        mx_records = [str(r.exchange) for r in dns.resolver.resolve(domain, 'MX')]
    except Exception:
        return {"domain_age_days": None, "registrar": "Unknown", "mx_records": []}
        
    return {
        "domain_age_days": domain_age_days,
        "registrar": w.registrar or "Unknown",
        "mx_records": mx_records
    }

# =============================================================================
# 5. MACHINE LEARNING MODULE (GROQ NLP)
# =============================================================================
def analyze_body_with_groq(subject: str, body: str) -> dict:
    if not body:
        return {"overall_bec_risk": 0, "urgency_flag": False, "suspicious_phrases": []}

    prompt = f"""You are a cybersecurity email analyzer. Analyze this email for social engineering, urgency, and fraud.
    Subject: {subject}
    Body: {body}

    Return ONLY a JSON object with exactly these keys:
    - "overall_bec_risk": integer from 0 to 100
    - "urgency_flag": boolean
    - "financial_request": boolean
    - "suspicious_phrases": array of strings (quote 1-3 suspicious sentences, or empty array)
    """
    
    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="openai/gpt-oss-20b",
            response_format={"type": "json_object"}, 
            temperature=0.0
        )
        return json.loads(chat_completion.choices[0].message.content)
    except Exception as e:
        print(f"Groq API Error: {e}")
        return {"overall_bec_risk": 0, "urgency_flag": False, "financial_request": False, "suspicious_phrases": []}

# =============================================================================
# 6. RISK SCORING ENGINE
# =============================================================================
def compute_risk_score(auth: dict, ip_intel: dict, domain_intel: dict, hops: int, mismatch: bool, nlp_data: dict) -> int:
    score = 0
    if auth.get("spf") != "pass": score += 20
    if auth.get("dkim") != "pass": score += 20
    if auth.get("dmarc") != "pass": score += 25
    
    if ip_intel.get("is_hosting_provider"): score += 15
    if ip_intel.get("is_proxy_or_vpn"): score += 10
    
    age = domain_intel.get("domain_age_days")
    if age is not None and age < 30: score += 20
    
    if hops > 8: score += 5
    if mismatch: score += 15
    
    # Factor in LLM NLP Risk (weighted at 40% of its reported risk)
    if nlp_data.get("overall_bec_risk"):
        score += int(nlp_data["overall_bec_risk"] * 0.4)
    if nlp_data.get("financial_request"):
        score += 15
        
    return min(score, 100)

def print_terminal_log(payload: dict, risk_score: int, auth_status: dict, ip_data: dict, domain_data: dict, hops: int, relay_chain: list, mismatch: bool, nlp: dict):
    """Outputs a clean, formatted terminal log with explainable score logic."""
    print("\n" + "="*60)
    print(f"🚨 [NEW EMAIL SCANNED] {payload['timestamp']}")
    print(f"Subject    : {payload['summary']['subject']}")
    print(f"From       : {payload['summary']['sender']}")
    print(f"Origin IP  : {payload['routing']['origin_ip']} ({ip_data.get('city', 'Unknown')}, {ip_data.get('country', 'Unknown')})")
    print(f"Infra      : Hosting={ip_data.get('is_hosting_provider')} | VPN/Proxy={ip_data.get('is_proxy_or_vpn')}")
    print(f"Auth       : SPF={auth_status['spf'].upper()} | DKIM={auth_status['dkim'].upper()} | DMARC={auth_status['dmarc'].upper()}")
    
    print("Relay Chain:")
    for hop in relay_chain:
        print(f"  └─ Hop {hop['hop']}: {hop['from_server']} -> {hop['by_server']} [{hop['ip']}]")

    # --- Groq AI Analysis Section ---
    print("\nGroq AI Body Analysis:")
    print(f"  ├─ BEC Risk Score    : {nlp.get('overall_bec_risk', 0)} / 100")
    print(f"  ├─ Urgency Flag      : {nlp.get('urgency_flag', False)}")
    print(f"  ├─ Financial Request : {nlp.get('financial_request', False)}")
    
    phrases = nlp.get("suspicious_phrases", [])
    if phrases:
        print("  └─ Flagged Phrases   :")
        for phrase in phrases:
            print(f"      • \"{phrase}\"")
    else:
        print("  └─ Flagged Phrases   : None (Clean / No social engineering detected)")

    # --- Score Logic ---
    print(f"\nRISK SCORE : {risk_score} / 100")
    print("Score Logic:")
    
    if auth_status.get("spf") != "pass": print("  +20 (SPF Failed)")
    if auth_status.get("dkim") != "pass": print("  +20 (DKIM Failed)")
    if auth_status.get("dmarc") != "pass": print("  +25 (DMARC Failed)")
    if ip_data.get("is_hosting_provider"): print("  +15 (Origin is Cloud/Hosting IP)")
    if ip_data.get("is_proxy_or_vpn"): print("  +10 (Origin is VPN/Proxy)")
    
    age = domain_data.get("domain_age_days")
    if age is not None and age < 30: 
        print(f"  +20 (Domain registered recently: {age} days ago)")
        
    if hops > 8: print(f"  +5  (Excessive routing: {hops} hops)")
    if mismatch: print("  +15 (Suspicious Urgency + DMARC Fail)")
    
    # NLP Score Factors
    if nlp.get("overall_bec_risk", 0) > 0:
        print(f"  +{int(nlp['overall_bec_risk'] * 0.4)}  (Groq NLP BEC Risk Weight)")
    if nlp.get("financial_request"):
        print("  +15 (Groq NLP: Payment Diversion / Financial Request Detected)")
    
    if risk_score == 0: 
        print("  +0  (All checks passed. Trusted infrastructure & clean body.)")
    print("="*60 + "\n")

# =============================================================================
# 7. MAIN INGESTION ENDPOINT
# =============================================================================
@app.post("/scan")
async def scan_email(request: Request):
    raw_body = await request.body()
    msg = message_from_bytes(raw_body, policy=default)
    
    # 1. Parse Authentication Headers
    auth_header = msg.get("Authentication-Results", "").lower()
    auth_status = {
        "spf": "pass" if "spf=pass" in auth_header else "fail",
        "dkim": "pass" if "dkim=pass" in auth_header else "fail",
        "dmarc": "pass" if "dmarc=pass" in auth_header else "fail"
    }

    # 2. Extract Origin IP and Build Relay Chain
    received_headers = msg.get_all("Received", [])
    hops = len(received_headers)
    origin_ip = None
    relay_chain = []
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    for idx, header in enumerate(reversed(received_headers)):
        clean_header = " ".join(header.split()) 
        ips = ip_pattern.findall(clean_header)
        
        from_match = re.search(r'from\s+(.*?)\s+by', clean_header, re.IGNORECASE)
        by_match = re.search(r'by\s+(.*?)\s+(?:with|id|;)', clean_header, re.IGNORECASE)
        
        hop_data = {
            "hop": idx + 1,
            "ip": ips[0] if ips else "Internal/Hidden",
            "from_server": from_match.group(1).split()[0] if from_match else "Unknown",
            "by_server": by_match.group(1).split()[0] if by_match else "Unknown"
        }
        relay_chain.append(hop_data)

        if not origin_ip:
            for ip in ips:
                if not ip.startswith(("10.", "192.168.", "127.", "172.")):
                    origin_ip = ip
                    break

    # 3. Domain & Sender extraction
    from_header = msg.get("From", "")
    subject = msg.get("Subject", "(No Subject)")
    from_domain = from_header.split("@")[-1].strip("<>") if "@" in from_header else None
    display_name_mismatch = "urgent" in subject.lower() and auth_status["dmarc"] == "fail"

    # 4. Extract Text & Run Machine Learning Model (Groq)
    clean_body = extract_clean_body(msg)
    print(f"\n[DEBUG] Raw Extracted Body Text:\n'''\n{clean_body}\n'''\n")

    nlp_analysis = analyze_body_with_groq(subject, clean_body)
    print(f"[DEBUG] Groq Raw Response: {nlp_analysis}")

    # 5. OSINT Enrichment
    ip_data = enrich_ip(origin_ip)
    domain_data = domain_intel(from_domain)
    
    # 6. Final Risk Scoring
    risk_score = compute_risk_score(auth_status, ip_data, domain_data, hops, display_name_mismatch, nlp_analysis)

    # Assemble JSON Payload
    payload = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "summary": {
            "risk_score": risk_score,
            "sender": from_header,
            "subject": subject
        },
        "authentication": auth_status,
        "routing": {
            "origin_ip": origin_ip or "Not Found",
            "total_hops": hops,
            "relay_chain": relay_chain
        },
        "intelligence": {
            "ip": ip_data,
            "domain": domain_data,
            "nlp": nlp_analysis
        }
    }

    # Output to Terminal
    print_terminal_log(
        payload=payload, 
        risk_score=risk_score, 
        auth_status=auth_status, 
        ip_data=ip_data, 
        domain_data=domain_data, 
        hops=hops, 
        relay_chain=relay_chain, 
        mismatch=display_name_mismatch, 
        nlp=nlp_analysis
    )

    # Stream to Frontend Dashboard
    await manager.broadcast(payload)

    return {"status": "ok", "message": "Broadcasted"}
