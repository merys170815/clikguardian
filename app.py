from flask import Flask, request, jsonify, render_template, abort
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
    r"/api/*": {"origins": "*"},
    r"/guard": {"origins": "*"}
})

# =========================
# 📦 Estado en memoria
# =========================
EVENTS = deque(maxlen=20000)

# Bloqueos por DEVICE e IP (IP queda como respaldo)
BLOCK_DEVICES = set()
BLOCK_IPS = set()

# Vistas recientes por device e IP (para contadores por ventana)
LAST_SEEN_DEVICE = defaultdict(deque)  # device_id -> deque[datetime]
LAST_SEEN_IP     = defaultdict(deque)  # ip        -> deque[datetime]

SETTINGS = {
    "risk_autoblock": True,
    "risk_threshold": 80,

    # Ventanas
    "repeat_window_seconds": 60,   # ventana dura para reglas en segundos
    "repeat_window_min": 60,       # ventana amplia (min) usada en panel/resumen

    # Reglas
    "repeat_required": 2,          # # de clics WA para autobloqueo (≤ ventana_seconds)
    "fast_dwell_ms": 600,          # umbral de dwell para visitas "ultrarrápidas"
    "fast_repeat_required": 3,     # repeticiones con dwell rápido para autobloqueo
}

BOT_UA_PAT = re.compile(
    r"bot|crawler|spider|preview|scan|archiver|linkchecker|monitor|pingdom|ahrefs|semrush|curl|wget",
    re.I
)

# =========================
# 🔧 Utilidades
# =========================
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

def _prune_window(dq: deque, cutoff: datetime):
    while dq and dq[0] < cutoff:
        dq.popleft()

def count_recent(dq: deque, seconds: int) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    _prune_window(dq, cutoff)
    return len(dq)

def touches_in_window_device(device_id: str, seconds: int) -> int:
    return count_recent(LAST_SEEN_DEVICE[device_id], seconds)

def touches_in_window_ip(ip: str, seconds: int) -> int:
    return count_recent(LAST_SEEN_IP[ip], seconds)

def compute_risk(ev: dict) -> dict:
    score, reasons = 0, []
    evt_type = (ev.get("type") or "").lower()

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

    geo = ev.get("geo") or {}
    if geo.get("country") and geo["country"] not in ("LOCAL","Colombia","CO"):
        score += 10
        reasons.append(f"País ≠ CO ({geo.get('country')})")
    if geo.get("vpn"):
        score += 15
        reasons.append("VPN/Hosting detectado")

    # ⚠️ Regla mitigante: click real en WhatsApp baja riesgo
    if evt_type == "whatsapp_click":
        score = max(0, score - 30)
        reasons.append("Click real en WhatsApp")

    score = max(0, min(100, score))
    return {"score": score, "suspicious": score >= SETTINGS["risk_threshold"], "reasons": reasons}

# =========================
# 🌐 Rutas de UI
# =========================
@app.route("/")
def home():
    # Se sirve la página; el front hará un POST /guard al iniciar con su device_id
    return render_template("index.html")

# Endpoint de guardia: el front lo llama APENAS carga con su device_id.
# Si está bloqueado → 403 y el front puede redirigir a una página de bloqueo.
@app.post("/guard")
def guard():
    data = request.get_json(force=True, silent=True) or {}
    device_id = data.get("device_id") or ""
    ip = get_client_ip()

    # Si está bloqueado por device → 403
    if device_id and device_id in BLOCK_DEVICES:
        logging.info(f"GUARD BLOCK device={device_id} ip={ip}")
        return jsonify({"blocked": True, "by": "device"}), 403

    # (opcional) Si también quieres bloquear por IP global
    if ip in BLOCK_IPS:
        logging.info(f"GUARD BLOCK ip={ip}")
        return jsonify({"blocked": True, "by": "ip"}), 403

    return jsonify({"blocked": False})

# =========================
# 📥 Tracking
# =========================
@app.route("/track", methods=["POST","OPTIONS"])
def track():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}

    # Identificadores
    ip = get_client_ip()
    device_id = (data.get("device_id") or data.get("fp") or "").strip()

    # Tiempos y contadores
    now = datetime.now(timezone.utc)
    LAST_SEEN_IP[ip].append(now)
    if device_id:
        LAST_SEEN_DEVICE[device_id].append(now)

    # Enriquecimiento
    data["ip"] = ip
    data["device_id"] = device_id or None
    data["ts"] = now_iso()
    data["geo"] = geo_lookup(ip)

    # Riesgo
    data["risk"] = compute_risk(data)
    risk = data["risk"]["score"]

    # Métricas de ventana
    window_sec = SETTINGS["repeat_window_seconds"]
    click_reqs = SETTINGS["repeat_required"]
    fast_ms = SETTINGS["fast_dwell_ms"]
    fast_reqs = SETTINGS["fast_repeat_required"]

    # Contadores por device prioritario; si no hay device, usar IP de respaldo
    base_key = device_id if device_id else ip
    base_is_device = bool(device_id)

    # Contamos eventos recientes en la ventana de segundos (no solo clicks)
    if base_is_device:
        repeats = touches_in_window_device(device_id, window_sec)
    else:
        repeats = touches_in_window_ip(ip, window_sec)

    dwell = data.get("dwell_ms") or 0
    evt_type = (data.get("type") or "").lower()

    # =========================
    # ⛔ LÓGICA DE AUTOBLOQUEO
    # =========================
    autoblock = False

    # Regla 1: score ≥ threshold
    if SETTINGS["risk_autoblock"] and risk >= SETTINGS["risk_threshold"]:
        autoblock = True

    # Regla 2: 2+ clics WA en ≤ ventana → autobloqueo
    # Para ser estrictos con clicks, usamos el tipo del evento
    if evt_type == "whatsapp_click":
        # Nota: "repeats" ya está contando el evento actual; es suficiente para la regla.
        if repeats >= click_reqs:
            autoblock = True

    # Regla 3: 3+ eventos en ventana con dwell < 600ms → autobloqueo
    if dwell and dwell < fast_ms and repeats >= fast_reqs:
        autoblock = True

    # Aplicar bloqueo
    if autoblock:
        if base_is_device:
            BLOCK_DEVICES.add(device_id)
            data["autoblocked"] = {"by": "device", "key": device_id}
            logging.warning(f"AUTOBLOCK DEVICE device_id={device_id} ip={ip} risk={risk} repeats={repeats} dwell={dwell}")
        else:
            BLOCK_IPS.add(ip)
            data["autoblocked"] = {"by": "ip", "key": ip}
            logging.warning(f"AUTOBLOCK IP ip={ip} risk={risk} repeats={repeats} dwell={dwell}")
    else:
        data["autoblocked"] = False

    # Estado de bloqueo actual
    data["blocked"] = (device_id in BLOCK_DEVICES) if device_id else (ip in BLOCK_IPS)

    # Guardar evento
    EVENTS.append(data)

    return ("", 204)

# =========================
# 📊 APIs de consulta
# =========================
@app.get("/api/events")
def api_events():
    limit = int(request.args.get("limit", 200))
    evs = list(EVENTS)[-limit:]
    evs.reverse()
    return jsonify({"events": evs})

@app.get("/api/blocklist")
def get_blocklist():
    # Combina bloqueos por device e IP
    out = {
        "devices": [],
        "ips": []
    }
    for d in sorted(BLOCK_DEVICES):
        out["devices"].append({
            "device_id": d,
            "last_seen_count_60s": touches_in_window_device(d, SETTINGS["repeat_window_seconds"]),
        })
    for ip in sorted(BLOCK_IPS):
        out["ips"].append({
            "ip": ip,
            "last_seen_count_60s": touches_in_window_ip(ip, SETTINGS["repeat_window_seconds"]),
            "sample_geo": geo_lookup(ip)
        })
    return jsonify(out)

# =========================
# 🛠️ APIs de bloqueo manual
# =========================
@app.post("/api/blockdevices")
def add_block_device():
    data = request.get_json(force=True) or {}
    device_id = (data.get("device_id") or "").strip()
    if device_id:
        BLOCK_DEVICES.add(device_id)
        logging.info(f"Manual block DEVICE: {device_id}")
        return jsonify({"ok": True, "blocked": device_id})
    return jsonify({"ok": False, "error": "device_id requerido"}), 400

@app.delete("/api/blockdevices")
def del_block_device():
    data = request.get_json(force=True) or {}
    device_id = (data.get("device_id") or "").strip()
    if device_id and device_id in BLOCK_DEVICES:
        BLOCK_DEVICES.remove(device_id)
        logging.info(f"Manual UNBLOCK DEVICE: {device_id}")
        return jsonify({"ok": True, "unblocked": device_id})
    return jsonify({"ok": False, "error": "device_id no encontrado"}), 404

@app.post("/api/blockips")
def add_block_ip():
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if ip:
        BLOCK_IPS.add(ip)
        logging.info(f"Manual block IP: {ip}")
        return jsonify({"ok": True, "blocked": ip})
    return jsonify({"ok": False, "error": "ip requerida"}), 400

@app.delete("/api/blockips")
def del_block_ip():
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if ip and ip in BLOCK_IPS:
        BLOCK_IPS.remove(ip)
        logging.info(f"Manual UNBLOCK IP: {ip}")
        return jsonify({"ok": True, "unblocked": ip})
    return jsonify({"ok": False, "error": "ip no encontrada"}), 404

# =========================
# ⚙️ Settings
# =========================
@app.get("/api/settings")
def get_settings():
    return jsonify(SETTINGS)

@app.post("/api/settings")
def set_settings():
    data = request.get_json(force=True) or {}
    for k in ("risk_autoblock","risk_threshold",
              "repeat_window_min","repeat_window_seconds",
              "repeat_required","fast_dwell_ms","fast_repeat_required"):
        if k in data:
            SETTINGS[k] = data[k]
    return jsonify({"ok": True, "settings": SETTINGS})

# =========================
# ▶️ Run
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
