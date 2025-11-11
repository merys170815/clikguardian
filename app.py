from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from functools import lru_cache
import requests, re, logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = Flask(__name__)

# CORS: /track solo desde tus sitios + pruebas locales + el propio panel
CORS(app, resources={
    r"/track": {"origins": [
        "https://medigoencas.com",
        "https://www.medigoencas.com",
        "https://clikguardian.onrender.com",
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost", "http://127.0.0.1"
    ]},
    r"/api/*": {"origins": "*"}
})

EVENTS = deque(maxlen=16000)
BLOCK  = set()
LAST_SEEN = defaultdict(deque)

SETTINGS = {
    "risk_autoblock": True,
    "risk_threshold": 80,
    "repeat_window_min": 60,   # ventana en minutos para conteo rápido (se usa también en ui)
    "repeat_window_seconds": 60,  # ventana para rule específica (segundos)
    "repeat_required": 2,      # cuantos clicks para autobloquear (2 según tu pedido)
    "max_dwell_ms": 60000      # dwell máximo por visita (60s)
}

BOT_UA_PAT = re.compile(
    r"bot|crawler|spider|preview|scan|archiver|linkchecker|monitor|pingdom|ahrefs|semrush|curl|wget",
    re.I
)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def get_client_ip():
    h = request.headers
    for k in ("CF-Connecting-IP","True-Client-IP","X-Real-IP"):
        v = h.get(k)
        if v: return v.strip()
    xff = h.get("X-Forwarded-For")
    if xff: return xff.split(",")[0].strip()
    return request.remote_addr

@lru_cache(maxsize=20000)
def geo_lookup(ip: str):
    try:
        if not ip or ip.startswith(("127.","10.","192.168.","::1")):
            return {"country":"LOCAL","region":"-","city":"-","district":"-",
                    "isp":"LAN","asn":"-","lat":0,"lon":0,"vpn":False}
        r = requests.get(f"https://ipwho.is/{ip}", timeout=4)
        j = r.json() if r.ok else {}
        conn = j.get("connection", {}) or {}
        sec  = j.get("security", {}) or {}
        return {
            "country": j.get("country","-"),
            "region":  j.get("region","-"),
            "city":    j.get("city","-"),
            "district":j.get("district","-"),
            "isp":     conn.get("isp") or j.get("org","-"),
            "asn":     conn.get("asn","-"),
            "lat":     j.get("latitude",0),
            "lon":     j.get("longitude",0),
            "vpn":     bool(sec.get("vpn",False))
        }
    except Exception:
        return {"country":"-","region":"-","city":"-","district":"-",
                "isp":"-","asn":"-","lat":0,"lon":0,"vpn":False}

def recent_events_for_ip(ip: str, seconds: int):
    """Devuelve eventos recientes para ip en los últimos `seconds` segundos (buscar en EVENTS)."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    res = []
    # iterar al revés es más eficiente: eventos recientes primero
    for ev in reversed(EVENTS):
        try:
            ev_ts = datetime.fromisoformat(ev.get("ts"))
        except Exception:
            continue
        if ev.get("ip") != ip:
            continue
        if ev_ts < cutoff:
            break
        res.append(ev)
    return res

def count_recent_clicks(ip: str, minutes: int) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    dq = LAST_SEEN[ip]
    while dq and dq[0] < cutoff:
        dq.popleft()
    return len(dq)

def compute_risk(ev: dict) -> dict:
    score, reasons = 0, []
    evt_type = (ev.get("type") or "").lower()

    dwell = ev.get("dwell_ms") or 0
    if dwell and dwell < 800:
        score += 30
        reasons.append("Dwell < 800ms")

    # User-Agent sospechoso
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

    # ✅ NUEVA REGLA: 2 clics en 1 minuto → bloquéalo
    if repeats >= 2:
        score += 40
        reasons.append("2+ clics en menos de 1 minuto")

    # ✅ NUEVA REGLA: visitas ultra rápidas repetidas
    if dwell < 600 and repeats >= 3:
        score += 35
        reasons.append("Visitas repetidas con dwell muy bajo (<600ms)")

    geo = ev.get("geo") or {}
    if geo.get("country") and geo["country"] not in ("LOCAL","Colombia","CO"):
        score += 10
        reasons.append(f"País ≠ CO ({geo.get('country')})")
    if geo.get("vpn"):
        score += 15
        reasons.append("VPN/Hosting detectado")

    # ✅ WhatsApp click debe bajar el riesgo
    if evt_type == "whatsapp_click":
        score = max(0, score - 30)
        reasons.append("Click real en WhatsApp")

    score = max(0, min(100, score))
    return {"score": score, "suspicious": score >= SETTINGS["risk_threshold"], "reasons": reasons}

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/track", methods=["POST","OPTIONS"])
def track():
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

    # ✅ AUTOBLOQUEO REAL AQUÍ
    risk = data["risk"]["score"]
    repeats = count_recent_clicks(ip, 1)  # último minuto
    dwell = data.get("dwell_ms") or 0

    autoblock = False

    # Regla 1: score ≥ 80
    if risk >= 80:
        autoblock = True

    # Regla 2: 2+ clics en 1 minuto
    if repeats >= 2:
        autoblock = True

    # Regla 3: 3+ visitas rápidas (<600ms)
    if dwell < 600 and repeats >= 3:
        autoblock = True

    if autoblock:
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
    # devolver adicionalmente el número de veces visto recientemente
    out = []
    for ip in sorted(BLOCK):
        out.append({
            "ip": ip,
            "last_seen_count": count_recent_clicks(ip, SETTINGS["repeat_window_min"]),
            "sample_geo": geo_lookup(ip)
        })
    return jsonify(out)

@app.post("/api/blocklist")
def add_block():
    data = request.get_json(force=True) or {}
    ip = data.get("ip")
    if ip:
        BLOCK.add(ip)
        logging.info(f"Manual block added: {ip}")
    return jsonify({"ok": True, "size": len(BLOCK)})

@app.delete("/api/blocklist")
def del_block():
    data = request.get_json(force=True) or {}
    ip = data.get("ip")
    if ip and ip in BLOCK:
        BLOCK.remove(ip)
        logging.info(f"Manual unblock: {ip}")
    return jsonify({"ok": True, "size": len(BLOCK)})

@app.get("/api/settings")
def get_settings():
    return jsonify(SETTINGS)

@app.post("/api/settings")
def set_settings():
    data = request.get_json(force=True) or {}
    for k in ("risk_autoblock","risk_threshold","repeat_window_min","repeat_window_seconds","repeat_required","max_dwell_ms"):
        if k in data:
            SETTINGS[k] = data[k]
    return jsonify({"ok": True, "settings": SETTINGS})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
