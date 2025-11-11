# ======================================================
# ✅ ClickGuardian — versión inteligente & estable 2025
# ======================================================

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from functools import lru_cache
import requests, re, logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = Flask(__name__)

# ✅ CORS
CORS(app, resources={
    r"/track": {"origins": "*"},
    r"/guard": {"origins": "*"},
    r"/api/*": {"origins": "*"},
})

# ✅ Estado global
EVENTS = deque(maxlen=50000)
BLOCK_DEVICES = set()
BLOCK_IPS     = set()
WHITELIST_DEVICES = set()
WHITELIST_IPS     = set()

LAST_SEEN_DEVICE = defaultdict(deque)
LAST_SEEN_IP     = defaultdict(deque)

BLOCKED_AT = {}   # device/ip -> datetime

# ✅ Configuración inteligente
SETTINGS = {
    "repeat_window_seconds": 60,      # ✅ doble click en 1 minuto
    "repeat_required": 2,             # ✅ mínimo 2 visitas en esa ventana
    "min_good_dwell_ms": 2000,        # ✅ visita real dura más de 2s
    "good_dwell_window_minutes": 60,  # ✅ buena visita válida por 1 hora
    "risk_autoblock": True,
    "risk_threshold": 80,
    "fast_dwell_ms": 600,
    "fast_repeat_required": 3,
    "autounblock_hours": 6,
    "block_ip_after_device_blocks": 3,
}

BOT_UA_PAT = re.compile(
    r"bot|crawler|spider|preview|scan|curl|wget|ahrefs|semrush|monitor|pingdom",
    re.I
)

# ======================================================
# ✅ Utilidades
# ======================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def get_client_ip():
    h = request.headers
    for key in ("CF-Connecting-IP", "True-Client-IP", "X-Real-IP"):
        if key in h:
            return h[key]
    if "X-Forwarded-For" in h:
        return h["X-Forwarded-For"].split(",")[0]
    return request.remote_addr

@lru_cache(maxsize=20000)
def geo_lookup(ip):
    try:
        if not ip or ip.startswith(("127.","10.","192.168.","::1")):
            return {"country":"LOCAL","vpn":False}
        r = requests.get(f"https://ipwho.is/{ip}", timeout=3)
        j = r.json()
        sec = j.get("security",{}) or {}
        return {"country": j.get("country"), "vpn": sec.get("vpn",False)}
    except:
        return {"country": "-", "vpn": False}

def prune_old(dq, cutoff):
    while dq and dq[0] < cutoff:
        dq.popleft()

def recent_touches(dq, seconds):
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    prune_old(dq, cutoff)
    return len(dq)

def had_good_dwell_recent(device_or_ip, minutes, min_ms):
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    for ev in reversed(EVENTS):
        if ev.get("device_id") != device_or_ip and ev.get("ip") != device_or_ip:
            continue
        try:
            ts = datetime.fromisoformat(ev["ts"])
        except:
            continue
        if ts < cutoff:
            break
        if ev["type"] == "land" and (ev.get("dwell_ms") or 0) >= min_ms:
            return True
    return False

def had_recent_whatsapp(device_or_ip, seconds):
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    for ev in reversed(EVENTS):
        if ev.get("device_id") != device_or_ip and ev.get("ip") != device_or_ip:
            continue
        try:
            ts = datetime.fromisoformat(ev["ts"])
        except:
            continue
        if ts < cutoff:
            break
        if (ev.get("type") or "").lower() == "whatsapp_click":
            return True
    return False

def compute_risk(ev):
    score = 0
    ua = (ev.get("ua") or "").lower()
    if BOT_UA_PAT.search(ua):
        score += 30
    if ev.get("geo",{}).get("vpn"):
        score += 15
    return min(score, 100)


# ======================================================
# ✅ FRONT RENDER
# ======================================================

@app.route("/")
def home():
    return render_template("index.html")


# ======================================================
# ✅ GUARD — usado por tu JS para saber si bloquear
# ======================================================

@app.post("/guard")
def guard():
    data = request.get_json(force=True, silent=True) or {}
    device_id = data.get("device_id")
    ip = get_client_ip()

    # Whitelist
    if device_id in WHITELIST_DEVICES or ip in WHITELIST_IPS:
        return jsonify({"blocked": False})

    # Bloqueado
    if device_id in BLOCK_DEVICES or ip in BLOCK_IPS:
        return jsonify({"blocked": True}), 403

    return jsonify({"blocked": False})


# ======================================================
# ✅ TRACK — corazón del sistema
# ======================================================

@app.post("/track")
def track():
    data = request.get_json(force=True, silent=True) or {}

    ip = get_client_ip()
    device = data.get("device_id") or None
    evt_type = (data.get("type") or "land").lower()
    now = datetime.now(timezone.utc)
    dwell = data.get("dwell_ms") or 0

    # Registrar times
    LAST_SEEN_IP[ip].append(now)
    if device:
        LAST_SEEN_DEVICE[device].append(now)

    # Construir evento
    event = {
        "ip": ip,
        "device_id": device,
        "ts": now_iso(),
        "type": evt_type,
        "url": data.get("url"),
        "ref": data.get("ref"),
        "ua": data.get("ua"),
        "dwell_ms": dwell,
        "geo": geo_lookup(ip),
    }

    # ✅ Desbloqueo automático
    if SETTINGS["autounblock_hours"] > 0:
        cutoff = now - timedelta(hours=SETTINGS["autounblock_hours"])
        for k, t in list(BLOCKED_AT.items()):
            if t < cutoff:
                BLOCK_IPS.discard(k)
                BLOCK_DEVICES.discard(k)
                BLOCKED_AT.pop(k, None)

    # ✅ Si ya está bloqueado → registrar y responder
    if device in BLOCK_DEVICES or ip in BLOCK_IPS:
        event["blocked"] = True
        EVENTS.append(event)
        return ("", 403)

    # ✅ Whitelist
    if device in WHITELIST_DEVICES or ip in WHITELIST_IPS:
        event["blocked"] = False
        EVENTS.append(event)
        return ("", 204)

    # ==================================================
    # ✅ LÓGICA PRINCIPAL QUE ME PEDISTE
    # ==================================================

    # 1) Contar repeticiones
    if device:
        repeats = recent_touches(LAST_SEEN_DEVICE[device], SETTINGS["repeat_window_seconds"])
    else:
        repeats = recent_touches(LAST_SEEN_IP[ip], SETTINGS["repeat_window_seconds"])

    # 2) Ver si hay WhatsApp en la ventana
    wa_recent = had_recent_whatsapp(device or ip, SETTINGS["repeat_window_seconds"])

    # 3) Ver si hubo visita buena en 1 hora
    good_visit = had_good_dwell_recent(device or ip, SETTINGS["good_dwell_window_minutes"],
                                       SETTINGS["min_good_dwell_ms"])

    autoblock = False
    reason = None

    # ✅ Si NO hay WhatsApp, NO hay buena visita y sí hay repeticiones → bloquear
    if evt_type == "land" and repeats >= SETTINGS["repeat_required"] and not wa_recent and not good_visit:
        autoblock = True
        reason = "double_click_no_good_visit"

    # ✅ Si dwell es demasiado bajo y repite mucho → sospechoso
    if dwell < SETTINGS["fast_dwell_ms"] and repeats >= SETTINGS["fast_repeat_required"]:
        autoblock = True
        reason = reason or "fast_repeats"

    # ✅ Riesgo alto (bots evidentes)
    risk_score = compute_risk(event)
    if SETTINGS["risk_autoblock"] and risk_score >= SETTINGS["risk_threshold"]:
        autoblock = True
        reason = reason or "risk_high"

    # ==================================================
    # ✅ Aplicar bloqueo si corresponde
    # ==================================================

    if autoblock:
        if device:
            BLOCK_DEVICES.add(device)
            BLOCKED_AT[device] = now
            event["autoblocked"] = {"by": "device", "reason": reason}
        else:
            BLOCK_IPS.add(ip)
            BLOCKED_AT[ip] = now
            event["autoblocked"] = {"by": "ip", "reason": reason}
    else:
        event["autoblocked"] = False

    event["blocked"] = autoblock
    EVENTS.append(event)

    return ("", 204)


# ======================================================
# ✅ API DE CONSULTAS
# ======================================================

@app.get("/api/events")
def api_events():
    return jsonify({"events": list(reversed(EVENTS))[:300]})


@app.get("/api/blocklist")
def blocklist():
    return jsonify({
        "devices": list(BLOCK_DEVICES),
        "ips": list(BLOCK_IPS),
    })


# ======================================================
# ✅ Run
# ======================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
