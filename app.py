# app.py
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from functools import lru_cache
import requests, re, logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
app = Flask(__name__)

# CORS: ajusta orígenes si hace falta
CORS(app, resources={
    r"/track": {"origins": [
        "https://medigoencas.com",
        "https://www.medigoencas.com",
        "https://clikguardian.onrender.com",
        "http://localhost",
        "http://127.0.0.1"
    ]},
    r"/api/*": {"origins": "*"},
    r"/guard": {"origins": "*"}
})

# -----------------------
# Estado en memoria
# -----------------------
EVENTS = deque(maxlen=30000)

BLOCK_DEVICES = set()   # device_id bloqueados
BLOCK_IPS     = set()   # IPs bloqueadas

WHITELIST_DEVICES = set()  # dispositivos que NUNCA autobloquean (tu equipo)
WHITELIST_IPS     = set()  # IPs de confianza

LAST_SEEN_DEVICE = defaultdict(deque)  # device_id -> deque[timestamps]
LAST_SEEN_IP     = defaultdict(deque)  # ip -> deque[timestamps]

# -----------------------
# Ajustes (modificables en /api/settings)
# -----------------------
SETTINGS = {
    "risk_autoblock": True,
    "risk_threshold": 80,
    "repeat_window_seconds": 60,     # ventana para contar repeticiones
    "repeat_window_min": 60,         # para UI
    "repeat_required": 2,            # clicks WA para regla
    "fast_dwell_ms": 600,            # dwell "rápido"
    "fast_repeat_required": 3,       # repeticiones rápidas para bloquear
    "min_good_dwell_ms": 2000,       # si hubo visita >= este dwell recientemente, no autobloquear por WA
    "good_dwell_window_minutes": 5,   # ventana para la comprobación anterior
}

BOT_UA_PAT = re.compile(r"bot|crawler|spider|preview|scan|archiver|linkchecker|monitor|pingdom|ahrefs|semrush|curl|wget", re.I)

# -----------------------
# Helpers
# -----------------------
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
            return {"country":"LOCAL","region":"-","city":"-","district":"-","isp":"LAN","asn":"-","lat":0,"lon":0,"vpn":False}
        r = requests.get(f"https://ipwho.is/{ip}", timeout=3)
        j = r.json() if r.ok else {}
        conn = j.get("connection",{}) or {}
        sec = j.get("security",{}) or {}
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
        return {"country":"-","region":"-","city":"-","district":"-","isp":"-","asn":"-","lat":0,"lon":0,"vpn":False}

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

def had_good_dwell_recently(device_id: str, minutes: int, min_ms: int) -> bool:
    """Si el device tuvo un 'land' con dwell >= min_ms en los últimos `minutes` minutos."""
    if not device_id: return False
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    # buscar en EVENTS (más simple)
    for ev in reversed(EVENTS):
        if ev.get("device_id") != device_id:
            continue
        try:
            ev_ts = datetime.fromisoformat(ev.get("ts"))
        except Exception:
            continue
        if ev_ts < cutoff:
            break
        if ev.get("type") == "land" and (ev.get("dwell_ms") or 0) >= min_ms:
            return True
    return False

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
        reasons.append("UA sospechosa")
    ref = (ev.get("ref") or "")
    url = (ev.get("url") or "")
    if ("google" in ref or "gclid=" in url) and "gclid=" not in url:
        score += 25
        reasons.append("Ads ref sin gclid")
    geo = ev.get("geo") or {}
    if geo.get("country") and geo["country"] not in ("LOCAL","Colombia","CO"):
        score += 10
        reasons.append("País ≠ CO")
    if geo.get("vpn"):
        score += 15
        reasons.append("VPN detectada")
    if evt_type == "whatsapp_click":
        score = max(0, score - 30)
        reasons.append("Click en WhatsApp (mitiga)")
    score = max(0, min(100, score))
    return {"score": score, "suspicious": score >= SETTINGS["risk_threshold"], "reasons": reasons}

# -----------------------
# Rutas UI
# -----------------------
@app.route("/")
def home():
    return render_template("index.html")

@app.post("/guard")
def guard():
    data = request.get_json(force=True, silent=True) or {}
    device_id = (data.get("device_id") or "").strip()
    ip = get_client_ip()

    # whitelist check
    if device_id and device_id in WHITELIST_DEVICES:
        return jsonify({"blocked": False, "by": "whitelist"})

    if ip and ip in WHITELIST_IPS:
        return jsonify({"blocked": False, "by": "whitelist"})

    # device-level block
    if device_id and device_id in BLOCK_DEVICES:
        logging.info(f"GUARD block device={device_id} ip={ip}")
        return jsonify({"blocked": True, "by": "device"}), 403

    # ip-level block
    if ip in BLOCK_IPS:
        logging.info(f"GUARD block ip={ip}")
        return jsonify({"blocked": True, "by": "ip"}), 403

    return jsonify({"blocked": False})

# -----------------------
# Tracking
# -----------------------
@app.route("/track", methods=["POST","OPTIONS"])
def track():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    ip = get_client_ip()
    device_id = (data.get("device_id") or data.get("fp") or "").strip() or None

    now = datetime.now(timezone.utc)
    LAST_SEEN_IP[ip].append(now)
    if device_id:
        LAST_SEEN_DEVICE[device_id].append(now)

    data["ip"] = ip
    data["device_id"] = device_id
    data["ts"] = now_iso()
    data["geo"] = geo_lookup(ip)
    data["risk"] = compute_risk(data)

    # ventana y contadores
    window_sec = SETTINGS["repeat_window_seconds"]
    click_reqs = SETTINGS["repeat_required"]
    fast_ms = SETTINGS["fast_dwell_ms"]
    fast_reqs = SETTINGS["fast_repeat_required"]

    base_is_device = bool(device_id)
    repeats = touches_in_window_device(device_id, window_sec) if base_is_device else touches_in_window_ip(ip, window_sec)
    dwell = data.get("dwell_ms") or 0
    evt_type = (data.get("type") or "").lower()

    # protections: never autoblock whitelist
    if (device_id and device_id in WHITELIST_DEVICES) or (ip and ip in WHITELIST_IPS):
        data["autoblocked"] = False
        data["blocked"] = False
        EVENTS.append(data)
        return ("", 204)

    # autoblock decision
    autoblock = False
    reason_ab = None

    # regla 1: risk alto
    if SETTINGS["risk_autoblock"] and data["risk"]["score"] >= SETTINGS["risk_threshold"]:
        autoblock = True
        reason_ab = "risk"

    # regla 2: 2+ clicks WA en ventana_seconds
    if evt_type == "whatsapp_click" and repeats >= click_reqs:
        # protección: si el dispositivo tuvo una visita "buena" recientemente, no autobloquea por WA
        if not had_good_dwell_recently(device_id, SETTINGS["good_dwell_window_minutes"], SETTINGS["min_good_dwell_ms"]):
            autoblock = True
            reason_ab = "wa_repeats"

    # regla 3: fast dwell repeats
    if dwell and dwell < fast_ms and repeats >= fast_reqs:
        autoblock = True
        reason_ab = "fast_repeats"

    if autoblock:
        if base_is_device:
            BLOCK_DEVICES.add(device_id)
            data["autoblocked"] = {"by": "device", "key": device_id, "reason": reason_ab}
            logging.warning(f"AUTOBLOCK device={device_id} ip={ip} reason={reason_ab} risk={data['risk']['score']} repeats={repeats} dwell={dwell}")
        else:
            BLOCK_IPS.add(ip)
            data["autoblocked"] = {"by": "ip", "key": ip, "reason": reason_ab}
            logging.warning(f"AUTOBLOCK ip={ip} reason={reason_ab} risk={data['risk']['score']} repeats={repeats} dwell={dwell}")
    else:
        data["autoblocked"] = False

    data["blocked"] = (device_id in BLOCK_DEVICES) if device_id else (ip in BLOCK_IPS)
    EVENTS.append(data)
    return ("", 204)

# -----------------------
# APIs: events + blocklist
# -----------------------
@app.get("/api/events")
def api_events():
    limit = int(request.args.get("limit", 200))
    evs = list(EVENTS)[-limit:]
    evs.reverse()
    out = []
    for ev in evs:
        device_id = ev.get("device_id")
        ip = ev.get("ip")
        blocked_device = device_id in BLOCK_DEVICES if device_id else False
        blocked_ip = ip in BLOCK_IPS
        blocked_now = blocked_device or blocked_ip
        blocked_by = "device" if blocked_device else ("ip" if blocked_ip else None)
        out.append({**ev, "blocked_now": blocked_now, "blocked_by": blocked_by})
    return jsonify({"events": out})

@app.get("/api/blocklist")
def get_blocklist():
    return jsonify({
        "devices": sorted(list(BLOCK_DEVICES)),
        "ips":     sorted(list(BLOCK_IPS)),
        "whitelist_devices": sorted(list(WHITELIST_DEVICES)),
        "whitelist_ips":     sorted(list(WHITELIST_IPS)),
    })

# -----------------------
# APIs de bloqueo / desbloqueo manual y whitelist
# -----------------------
@app.post("/api/blockdevices")
def add_block_device():
    data = request.get_json(force=True) or {}
    device_id = (data.get("device_id") or "").strip()
    if not device_id:
        return jsonify({"ok": False, "error": "device_id requerido"}), 400
    BLOCK_DEVICES.add(device_id)
    logging.info(f"Manual block device: {device_id}")
    return jsonify({"ok": True, "blocked": device_id})

@app.delete("/api/blockdevices")
def del_block_device():
    data = request.get_json(force=True) or {}
    device_id = (data.get("device_id") or "").strip()
    if device_id in BLOCK_DEVICES:
        BLOCK_DEVICES.remove(device_id)
        logging.info(f"Manual unblock device: {device_id}")
        return jsonify({"ok": True, "unblocked": device_id})
    return jsonify({"ok": False, "error": "device_id no encontrado"}), 404

@app.post("/api/blockips")
def add_block_ip():
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "ip requerida"}), 400
    BLOCK_IPS.add(ip)
    logging.info(f"Manual block ip: {ip}")
    return jsonify({"ok": True, "blocked": ip})

@app.delete("/api/blockips")
def del_block_ip():
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if ip in BLOCK_IPS:
        BLOCK_IPS.remove(ip)
        logging.info(f"Manual unblock ip: {ip}")
        return jsonify({"ok": True, "unblocked": ip})
    return jsonify({"ok": False, "error": "ip no encontrada"}), 404

# whitelist endpoints
@app.post("/api/whitelist/devices")
def add_whitelist_device():
    data = request.get_json(force=True) or {}
    d = (data.get("device_id") or "").strip()
    if not d:
        return jsonify({"ok": False, "error": "device_id requerido"}), 400
    WHITELIST_DEVICES.add(d)
    logging.info(f"Whitelist device add: {d}")
    return jsonify({"ok": True, "added": d})

@app.delete("/api/whitelist/devices")
def del_whitelist_device():
    data = request.get_json(force=True) or {}
    d = (data.get("device_id") or "").strip()
    if d in WHITELIST_DEVICES:
        WHITELIST_DEVICES.remove(d)
        logging.info(f"Whitelist device removed: {d}")
        return jsonify({"ok": True, "removed": d})
    return jsonify({"ok": False, "error": "device_id no encontrado"}), 404

# -----------------------
# Settings
# -----------------------
@app.get("/api/settings")
def get_settings():
    return jsonify(SETTINGS)

@app.post("/api/settings")
def set_settings():
    data = request.get_json(force=True) or {}
    allowed = ("risk_autoblock","risk_threshold","repeat_window_seconds","repeat_window_min",
               "repeat_required","fast_dwell_ms","fast_repeat_required","min_good_dwell_ms","good_dwell_window_minutes")
    for k in allowed:
        if k in data:
            SETTINGS[k] = data[k]
    logging.info(f"Settings updated: {data}")
    return jsonify({"ok": True, "settings": SETTINGS})

# -----------------------
# Run
# -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
