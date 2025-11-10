# app.py
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from functools import lru_cache
import requests, re

app = Flask(__name__)

# ==== CORS: solo tu sitio puede enviar /track desde el browser ====
CORS(app, resources={
    r"/track": {"origins": ["https://medigoencas.com", "https://www.medigoencas.com"]},
    r"/api/*": {"origins": "*"}  # el panel puede consultar desde cualquier origen
})

# ====== Estado en memoria ======
EVENTS = deque(maxlen=8000)
BLOCK  = set()
LAST_SEEN = defaultdict(deque)

SETTINGS = {
    "risk_autoblock": True,
    "risk_threshold": 80,
    "repeat_window_min": 60,
}

BOT_UA_PAT = re.compile(
    r"bot|crawler|spider|preview|scan|archiver|linkchecker|monitor|pingdom|ahrefs|semrush|curl|wget",
    re.I
)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def get_client_ip():
    """
    Toma la IP real considerando cabeceras típicas de proxy/CDN.
    Orden de preferencia:
    - CF-Connecting-IP (Cloudflare)
    - True-Client-IP (algunas CDNs)
    - X-Real-IP (reverse proxy)
    - X-Forwarded-For (lista, tomamos el primer cliente)
    - request.remote_addr
    """
    headers = request.headers
    for h in ("CF-Connecting-IP", "True-Client-IP", "X-Real-IP"):
        ip = headers.get(h)
        if ip:
            return ip.strip()
    xff = headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr

@lru_cache(maxsize=20000)
def geo_lookup(ip: str):
    """
    Geolocaliza IP con ipwho.is (rápido y sin clave).
    Devuelve city/region/district/lat/lon/isp/asn/vpn.
    """
    try:
        if not ip or ip.startswith(("127.", "10.", "192.168.", "::1")):
            return {
                "country": "LOCAL", "region": "-", "city": "-", "district": "-",
                "isp": "LAN", "asn": "-", "lat": 0, "lon": 0, "vpn": False
            }
        r = requests.get(f"https://ipwho.is/{ip}", timeout=4)
        j = r.json() if r.ok else {}
        conn = j.get("connection", {}) or {}
        sec  = j.get("security", {}) or {}
        return {
            "country":  j.get("country", "-"),
            "region":   j.get("region", "-"),
            "city":     j.get("city", "-"),
            "district": j.get("district", "-"),
            "isp":      conn.get("isp") or j.get("org", "-"),
            "asn":      conn.get("asn", "-"),
            "lat":      j.get("latitude", 0),
            "lon":      j.get("longitude", 0),
            "vpn":      bool(sec.get("vpn", False))
        }
    except Exception:
        return {
            "country": "-", "region": "-", "city": "-", "district": "-",
            "isp": "-", "asn": "-", "lat": 0, "lon": 0, "vpn": False
        }

def count_recent_clicks(ip: str, minutes: int) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    dq = LAST_SEEN[ip]
    while dq and dq[0] < cutoff:
        dq.popleft()
    return len(dq)

def compute_risk(ev: dict) -> dict:
    score, reasons = 0, []
    dwell = ev.get("dwell_ms") or 0
    if dwell and dwell < 800:
        score += 30; reasons.append("Dwell < 800ms")
    ua = (ev.get("ua") or "").lower()
    if BOT_UA_PAT.search(ua):
        score += 25; reasons.append("User-Agent tipo bot")
    ref = (ev.get("ref") or ""); url = (ev.get("url") or "")
    if ("google" in ref or "gclid=" in url) and "gclid=" not in url:
        score += 25; reasons.append("Ads ref sin gclid")
    ip = ev.get("ip") or ""
    repeats = count_recent_clicks(ip, SETTINGS["repeat_window_min"])
    if repeats >= 3:
        score += 20; reasons.append(f"Repeticiones en {SETTINGS['repeat_window_min']}min: {repeats}")
    geo = ev.get("geo") or {}
    if geo.get("country") and geo["country"] not in ("LOCAL", "Colombia", "CO"):
        score += 10; reasons.append(f"País ≠ CO ({geo.get('country')})")
    if geo.get("vpn"):  # penaliza VPN/hosting
        score += 15; reasons.append("VPN/Hosting detectado")

    score = max(0, min(100, score))
    return {"score": score, "suspicious": score >= SETTINGS["risk_threshold"], "reasons": reasons}

# ================= Rutas =================

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/track", methods=["POST", "OPTIONS"])
def track():
    # OPTIONS lo maneja CORS; respondemos sin cuerpo
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}

    ip = get_client_ip()
    LAST_SEEN[ip].append(datetime.now(timezone.utc))

    data["ip"] = ip
    data["ts"] = now_iso()
    data["blocked"] = ip in BLOCK
    data["geo"] = geo_lookup(ip)
    data["risk"] = compute_risk(data)

    # Auto-bloqueo
    if SETTINGS["risk_autoblock"] and data["risk"]["suspicious"]:
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
    # Si lo corres local y pruebas desde móvil/otra PC, usa 0.0.0.0
    app.run(host="0.0.0.0", port=5000, debug=True)
