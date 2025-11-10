# app.py
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from functools import lru_cache
import requests
import re
import json
import os

app = Flask(__name__)

# -------- Persistencia blocklist ----------
BLOCKLIST_FILE = os.path.join(os.path.dirname(__file__), "blocklist.json")

def load_blocklist():
    try:
        with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return set(data.get("blocked", []))
    except Exception:
        return set()

def save_blocklist(blockset):
    try:
        with open(BLOCKLIST_FILE, "w", encoding="utf-8") as f:
            json.dump({"blocked": sorted(list(blockset))}, f, ensure_ascii=False, indent=2)
    except Exception as e:
        app.logger.warning("No se pudo guardar blocklist: %s", e)

# Cargar bloqueados al arrancar
BLOCK = load_blocklist()

# ====== Memoria runtime ======
EVENTS = deque(maxlen=8000)
LAST_SEEN = defaultdict(deque)

# ====== Ajustes ======
SETTINGS = {
    "risk_autoblock": True,
    "risk_threshold": 80,
    "repeat_window_min": 60,
}

# ====== CORS para tu dominio ======
allowed_origins = [
    "https://medigoencasa.com",
    "https://www.medigoencasa.com"
]

CORS(app, resources={r"/*": {"origins": allowed_origins}}, supports_credentials=True)

# ====== Utilidades ======
BOT_UA_PAT = re.compile(
    r"bot|crawler|spider|preview|scan|archiver|linkchecker|monitor|pingdom|ahrefs|semrush|curl|wget",
    re.I
)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

@lru_cache(maxsize=20000)
def geo_lookup(ip: str):
    try:
        if not ip:
            return {"country": "-", "region": "-", "city": "-", "org": "-"}
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip == "::1":
            return {"country": "LOCAL", "region": "-", "city": "-", "org": "LAN"}
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=4)
        j = r.json() if r.ok else {}
        return {
            "country": j.get("country_name") or j.get("country") or "-",
            "region":  j.get("region") or j.get("region_code") or "-",
            "city":    j.get("city") or "-",
            "org":     j.get("org") or j.get("asn") or "-",
        }
    except Exception:
        return {"country": "-", "region": "-", "city": "-", "org": "-"}

def count_recent_clicks(ip: str, minutes: int) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    dq = LAST_SEEN[ip]
    while dq and dq[0] < cutoff:
        dq.popleft()
    return len(dq)

def compute_risk(ev: dict) -> dict:
    score = 0
    reasons = []
    dwell = ev.get("dwell_ms") or 0
    if dwell and dwell < 800:
        score += 30
        reasons.append("Dwell < 800ms")
    ua = (ev.get("ua") or "").lower()
    if BOT_UA_PAT.search(ua):
        score += 25
        reasons.append("User-Agent tipo bot")
    ref = (ev.get("ref") or "")
    url = (ev.get("url") or "")
    if ("google" in ref or "gclid=" in url) and "gclid=" not in url:
        score += 25
        reasons.append("Ads ref sin gclid")
    ip = ev.get("ip") or ""
    repeats = count_recent_clicks(ip, SETTINGS["repeat_window_min"])
    if repeats >= 3:
        score += 20
        reasons.append(f"Repeticiones en {SETTINGS['repeat_window_min']}min: {repeats}")
    geo = ev.get("geo") or {}
    if geo.get("country") and geo["country"] not in ("LOCAL", "Colombia", "CO"):
        score += 10
        reasons.append(f"País ≠ CO ({geo.get('country')})")
    score = max(0, min(100, score))
    return {"score": score, "suspicious": score >= SETTINGS["risk_threshold"], "reasons": reasons}

# ====== Rutas ======
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/track", methods=["POST", "OPTIONS"])
def track():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}

    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or request.remote_addr
    ip = (ip.split(",")[0]).strip() if ip else ip

    LAST_SEEN[ip].append(datetime.now(timezone.utc))
    data["ip"] = ip
    data["ts"] = now_iso()
    data["blocked"] = ip in BLOCK
    data["geo"] = geo_lookup(ip)
    risk = compute_risk(data)
    data["risk"] = risk

    if SETTINGS["risk_autoblock"] and risk["suspicious"]:
        BLOCK.add(ip)
        save_blocklist(BLOCK)
        data["autoblocked"] = True
    else:
        data["autoblocked"] = False

    EVENTS.append(data)
    return ("", 204)

@app.route("/api/events", methods=["GET"])
def api_events():
    limit = int(request.args.get("limit", 200))
    evs = list(EVENTS)[-limit:]
    evs.reverse()
    return jsonify({"events": evs})

@app.route("/api/blocklist", methods=["GET"])
def get_blocklist():
    return jsonify(sorted(list(BLOCK)))

@app.route("/api/blocklist", methods=["POST"])
def add_block():
    data = request.get_json(force=True) or {}
    ip = data.get("ip")
    if ip:
        BLOCK.add(ip)
        save_blocklist(BLOCK)
    return jsonify({"ok": True, "size": len(BLOCK)})

@app.route("/api/blocklist", methods=["DELETE"])
def del_block():
    data = request.get_json(force=True) or {}
    ip = data.get("ip")
    if ip and ip in BLOCK:
        BLOCK.remove(ip)
        save_blocklist(BLOCK)
    return jsonify({"ok": True, "size": len(BLOCK)})

@app.route("/api/settings", methods=["GET"])
def get_settings():
    return jsonify(SETTINGS)

@app.route("/api/settings", methods=["POST"])
def set_settings():
    data = request.get_json(force=True) or {}
    for k in ("risk_autoblock", "risk_threshold", "repeat_window_min"):
        if k in data:
            SETTINGS[k] = data[k]
    return jsonify({"ok": True, "settings": SETTINGS})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
