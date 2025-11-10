from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from functools import lru_cache
import requests
import re

# ==================================================
# ✅ INICIALIZAR APP + ACTIVAR CORS PARA TU DOMINIO
# ==================================================
app = Flask(__name__)

CORS(app, resources={
    r"/track": {
        "origins": [
            "https://medigoencas.com",
            "https://www.medigoencas.com"
        ]
    }
})

# ====== Memoria ======
EVENTS = deque(maxlen=8000)     # historial rotativo
BLOCK  = set()                  # IPs bloqueadas
LAST_SEEN = defaultdict(deque)  # últimos timestamps por IP (para repetición)

# ====== Ajustes (editables vía API) ======
SETTINGS = {
    "risk_autoblock": True,   # si True, auto-bloquear cuando supere risk_threshold
    "risk_threshold": 80,     # 0..100
    "repeat_window_min": 60,  # ventana para contar repetidos (min)
}

# ====== Utilidades ======
BOT_UA_PAT = re.compile(
    r"bot|crawler|spider|preview|scan|archiver|linkchecker|monitor|pingdom|ahrefs|semrush|curl|wget",
    re.I
)

def now_iso():
    return datetime.now(timezone.utc).isoformat()
@lru_cache(maxsize=20000)
def geo_lookup(ip: str):
    """Geo e ISP usando ipwho.is (gratis y sin límites)."""
    try:
        # IP locales no deben consultarse
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip == "::1":
            return {"country": "LOCAL", "region": "-", "city": "-", "org": "LAN"}

        # Consulta al API de ipwho.is
        r = requests.get(f"https://ipwho.is/{ip}", timeout=4)
        j = r.json() if r.ok else {}

        return {
            "country": j.get("country") or "-",
            "region":  j.get("region") or "-",
            "city":    j.get("city") or "-",
            "org":     j.get("connection", {}).get("isp") or "-"
        }
    except Exception:
        return {"country": "-", "region": "-", "city": "-", "org": "-"}

def count_recent_clicks(ip: str, minutes: int) -> int:
    """Cuenta clicks del IP en los últimos N minutos y depura su deque."""
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
    return {
        "score": score,
        "suspicious": score >= SETTINGS["risk_threshold"],
        "reasons": reasons
    }

# ==================================================
# ✅ RUTAS
# ==================================================

@app.route("/")
def home():
    return render_template("index.html")

@app.post("/track")
def track():
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
        data["autoblocked"] = True
    else:
        data["autoblocked"] = False

    EVENTS.append(data)
    return ("", 204)

@app.get("/api/events")
def api_events():
    limit = int(request.args.get("limit", 200))
    evs = list(EVENTS)[-limit:]
    evs.reverse()
    return jsonify({"events": evs})

@app.get("/api/blocklist")
def get_blocklist():
    return jsonify(sorted(list(BLOCK)))

@app.post("/api/blocklist")
def add_block():
    data = request.get_json(force=True) or {}
    ip = data.get("ip")
    if ip:
        BLOCK.add(ip)
    return jsonify({"ok": True, "size": len(BLOCK)})

@app.delete("/api/blocklist")
def del_block():
    data = request.get_json(force=True) or {}
    ip = data.get("ip")
    if ip and ip in BLOCK:
        BLOCK.remove(ip)
    return jsonify({"ok": True, "size": len(BLOCK)})

@app.get("/api/settings")
def get_settings():
    return jsonify(SETTINGS)

@app.post("/api/settings")
def set_settings():
    data = request.get_json(force=True) or {}
    for k in ("risk_autoblock", "risk_threshold", "repeat_window_min"):
        if k in data:
            SETTINGS[k] = data[k]
    return jsonify({"ok": True, "settings": SETTINGS})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
