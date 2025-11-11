# ======================================================
# 🚨 ClickGuardian PRO — Backend FINAL ✅
# Bloqueo inmediato + máscara + 6 capas anticlicks
# ======================================================

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from functools import lru_cache
import requests, re, logging

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

## ✅ CORS — necesario para conectar con tu web en producción
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


# ==========================
# ✅ Estado
# ==========================
EVENTS = deque(maxlen=50000)

BLOCK_DEVICES = set()
BLOCK_IPS = set()

SOFT_BLOCK_DEVICES = {}
SOFT_BLOCK_IPS = {}

MASK_DEVICES = {}
MASK_IPS = {}

WHITELIST_DEVICES = set()
WHITELIST_IPS = set()

LAST_SEEN_DEVICE = defaultdict(deque)
LAST_SEEN_IP = defaultdict(deque)

DAILY_COUNTER_DEVICE = defaultdict(lambda: defaultdict(int))
DAILY_COUNTER_IP = defaultdict(lambda: defaultdict(int))

# ==========================
# ✅ Parámetros
# ==========================
SETTINGS = {
    "repeat_window_seconds": 60,
    "repeat_required": 2,

    "fast_dwell_ms": 800,

    "daily_soft_mask": 3,
    "daily_soft_mask_hours": 6,

    "daily_soft_block": 5,
    "daily_soft_block_hours": 72,

    "daily_perm_block": 7,

    "ghost_grace_seconds": 10,
    "ghost_mask_hours": 24,

    "vpn_mask": True,
    "vpn_block_on_repeats": 2,
    "vpn_block_hours": 72,

    "refresh_window_seconds": 90,
    "refresh_threshold": 3,
    "refresh_mask_hours": 12,
    "refresh_block_hours": 48,

    "night_start_hour": 0,
    "night_end_hour": 5,
    "night_repeat_to_block": 3,
    "night_block_hours": 24,

    "risk_autoblock": True,
    "risk_threshold": 80,
}

BOT_UA_PAT = re.compile(
    r"bot|crawler|preview|curl|wget|headless|scrap|scan",
    re.I
)

# ==========================
# ✅ Helpers
# ==========================
def now_utc():
    return datetime.now(timezone.utc)

def now_iso():
    return now_utc().isoformat()

def bogota_now():
    return now_utc() + timedelta(hours=-5)

def prune_expired(dct):
    expired = [k for k, exp in dct.items() if exp <= now_utc()]
    for k in expired:
        del dct[k]

def get_ip():
    return (
        request.headers.get("CF-Connecting-IP") or
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or
        request.remote_addr
    )

@lru_cache(maxsize=20000)
def geo(ip):
    try:
        if ip.startswith(("127.","192.168","10.")):
            return {"country":"LOCAL","vpn":False}
        r = requests.get(f"https://ipwho.is/{ip}", timeout=3).json()
        sec = r.get("security", {})
        return {
            "country": r.get("country","?"),
            "vpn": bool(sec.get("vpn",False))
        }
    except:
        return {"country":"?","vpn":False}

def touches(dq, sec):
    cutoff = now_utc() - timedelta(seconds=sec)
    while dq and dq[0] < cutoff:
        dq.popleft()
    return len(dq)

def apply_mask(device=None, ip=None, hours=6):
    exp = now_utc() + timedelta(hours=hours)
    if device: MASK_DEVICES[device] = exp
    if ip: MASK_IPS[ip] = exp

def soft_block(device=None, ip=None, hours=72):
    exp = now_utc() + timedelta(hours=hours)
    if device: SOFT_BLOCK_DEVICES[device] = exp
    if ip: SOFT_BLOCK_IPS[ip] = exp

# ==========================
# ✅ ROUTE: GUARD (bloqueo inmediato)
# ==========================
@app.post("/guard")
def guard():
    prune_expired(SOFT_BLOCK_DEVICES)
    prune_expired(SOFT_BLOCK_IPS)
    prune_expired(MASK_DEVICES)
    prune_expired(MASK_IPS)

    data = request.get_json(force=True, silent=True) or {}
    device = (data.get("device_id") or "").strip()
    ip = get_ip()

    # ✅ Whitelist
    if device in WHITELIST_DEVICES or ip in WHITELIST_IPS:
        return jsonify({"blocked": False})

    # ✅ BLOCK PERMANENTE
    if device in BLOCK_DEVICES or ip in BLOCK_IPS:
        return jsonify({"blocked": True}), 403

    # ✅ BLOCK SUAVE
    if device in SOFT_BLOCK_DEVICES or ip in SOFT_BLOCK_IPS:
        return jsonify({"blocked": True}), 403

    # ✅ MASK (capa de engaño)
    if device in MASK_DEVICES or ip in MASK_IPS:
        return jsonify({"blocked": False, "mask": True})

    # ✅ OK
    return jsonify({"blocked": False})

# ==========================
# ✅ ROUTE: TRACK
# ==========================
@app.post("/track")
def track():
    prune_expired(SOFT_BLOCK_DEVICES)
    prune_expired(SOFT_BLOCK_IPS)
    prune_expired(MASK_DEVICES)
    prune_expired(MASK_IPS)

    data = request.get_json(force=True, silent=True) or {}

    evt = (data.get("type") or "").lower()
    ip = get_ip()
    device = (data.get("device_id") or "").strip()

    now = now_utc()
    LAST_SEEN_IP[ip].append(now)
    if device:
        LAST_SEEN_DEVICE[device].append(now)

    # =============================
    # ✅ SANCIONES SI YA ESTÁ BLOQUEADO
    # =============================
    if device in BLOCK_DEVICES or ip in BLOCK_IPS:
        return ("", 204)
    if device in SOFT_BLOCK_DEVICES or ip in SOFT_BLOCK_IPS:
        return ("", 204)

    # =============================
    # ✅ REGLAS
    # =============================
    geo_data = geo(ip)
    reps = touches(LAST_SEEN_DEVICE[device], SETTINGS["repeat_window_seconds"]) if device else touches(LAST_SEEN_IP[ip], SETTINGS["repeat_window_seconds"])

    # ✅ Dwell time
    dwell = data.get("dwell_ms") or 0

    # ✅ Anti VPN
    if geo_data["vpn"]:
        apply_mask(device, ip, 12)

    # ✅ Repeticiones rápidas
    if evt in ("land","refresh") and reps >= SETTINGS["repeat_required"]:
        apply_mask(device, ip, 12)

    # ✅ Dwell muy rápido
    if dwell and dwell < SETTINGS["fast_dwell_ms"]:
        soft_block(device, ip, 24)

    # ✅ Anti nocturno
    hr = bogota_now().hour
    if 0 <= hr < 5 and reps >= SETTINGS["night_repeat_to_block"]:
        soft_block(device, ip, 24)

    # ✅ Registrar evento
    data["ts"] = now_iso()
    data["ip"] = ip
    data["geo"] = geo_data
    EVENTS.append(data)

    return ("", 204)

# ==========================
# ✅ PANEL
# ==========================
@app.get("/api/events")
def api_events():
    out = list(EVENTS)[-200:]
    out.reverse()
    return jsonify({"events": out})

# ==========================
# ✅ BLOQUES MANUALES
# ==========================
@app.post("/api/blockdevices")
def block_device():
    data = request.get_json(force=True)
    d = data.get("device_id")
    BLOCK_DEVICES.add(d)
    return jsonify({"ok": True})
@app.get("/")
def root():
    return "<h1>✅ ClickGuardian corriendo</h1>"

@app.post("/api/blockips")
def block_ip():
    data = request.get_json(force=True)
    ip = data.get("ip")
    BLOCK_IPS.add(ip)
    return jsonify({"ok": True})

# ==========================
# ✅ RUN
# ==========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
