# ======================================================
# 🚨 ClickGuardian PRO v7 — 6 capas + Panel + Mask + Block
# ✅ Versión estable y funcional (probada)
# ======================================================

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from functools import lru_cache
import requests, re, logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = Flask(__name__)

# ✅ CORS – muy importante
CORS(app, resources={
    r"/track": {"origins": [
        "https://medigoencas.com",
        "https://www.medigoencas.com",
        "https://clikguardian.onrender.com",
        "http://localhost",
        "http://127.0.0.1"
    ]},
    r"/guard": {"origins": "*"},
    r"/api/*": {"origins": "*"}
})

# ======================================================
# ✅ Estado en memoria
# ======================================================
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

# ======================================================
# ✅ Parámetros
# ======================================================
SETTINGS = {
    "repeat_window_seconds": 60,
    "repeat_required": 2,

    "fast_dwell_ms": 800,

    "daily_soft_mask": 3,
    "daily_soft_mask_hours": 6,

    "daily_soft_block": 5,
    "daily_soft_block_hours": 72,

    "daily_perm_block": 7,

    "ghost_mask_hours": 24,
    "ghost_block_hours": 72,

    "vpn_mask_hours": 24,
    "vpn_block_hours": 72,

    "refresh_window_seconds": 90,
    "refresh_threshold": 3,
    "refresh_mask_hours": 12,
    "refresh_block_hours": 48,

    "night_start_hour": 0,
    "night_end_hour": 5,
    "night_block_hours": 24,

    "risk_threshold": 80
}

BOT_UA_PAT = re.compile(
    r"bot|crawler|spider|preview|scan|curl|wget|headless|selenium|scrap",
    re.I
)

# ======================================================
# ✅ Helpers
# ======================================================

def now_utc():
    return datetime.now(timezone.utc)

def now_iso():
    return now_utc().isoformat()

def bogota_now():
    return now_utc() + timedelta(hours=-5)

def prune_expired(d):
    remove = [k for k, v in d.items() if v <= now_utc()]
    for k in remove:
        del d[k]

def get_ip():
    return (
        request.headers.get("CF-Connecting-IP") or
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or
        request.remote_addr
    )

@lru_cache(maxsize=20000)
def geo(ip):
    try:
        if ip.startswith(("127.", "10.", "192.168")):
            return {"country": "LOCAL", "vpn": False}
        r = requests.get(f"https://ipwho.is/{ip}", timeout=3).json()
        return {
            "country": r.get("country", "?"),
            "vpn": bool(r.get("security", {}).get("vpn", False))
        }
    except:
        return {"country": "?", "vpn": False}

def touches(dq, seconds):
    cutoff = now_utc() - timedelta(seconds=seconds)
    while dq and dq[0] < cutoff:
        dq.popleft()
    return len(dq)

def soft_block(device=None, ip=None, hours=24):
    exp = now_utc() + timedelta(hours=hours)
    if device: SOFT_BLOCK_DEVICES[device] = exp
    if ip: SOFT_BLOCK_IPS[ip] = exp

def mask(device=None, ip=None, hours=12):
    exp = now_utc() + timedelta(hours=hours)
    if device: MASK_DEVICES[device] = exp
    if ip: MASK_IPS[ip] = exp

# ======================================================
# ✅ RUTA PRINCIPAL (Tu panel)
# ======================================================
@app.route("/")
def root():
    return render_template("index.html")

# ======================================================
# ✅ GUARD – Bloqueo inmediato antes de cargar tu página
# ======================================================
@app.post("/guard")
def guard():
    prune_expired(SOFT_BLOCK_DEVICES)
    prune_expired(SOFT_BLOCK_IPS)
    prune_expired(MASK_DEVICES)
    prune_expired(MASK_IPS)

    data = request.get_json(force=True, silent=True) or {}
    device = (data.get("device_id") or "").strip()
    ip = get_ip()

    if device in WHITELIST_DEVICES or ip in WHITELIST_IPS:
        return jsonify({"blocked": False})

    if device in BLOCK_DEVICES or ip in BLOCK_IPS:
        return jsonify({"blocked": True}), 403

    if device in SOFT_BLOCK_DEVICES or ip in SOFT_BLOCK_IPS:
        return jsonify({"blocked": True}), 403

    if device in MASK_DEVICES or ip in MASK_IPS:
        return jsonify({"blocked": False, "mask": True})

    return jsonify({"blocked": False})

# ======================================================
# ✅ TRACK – Aquí se aplican las 6 capas
# ======================================================
@app.post("/track")
def track():
    prune_expired(SOFT_BLOCK_DEVICES)
    prune_expired(SOFT_BLOCK_IPS)
    prune_expired(MASK_DEVICES)
    prune_expired(MASK_IPS)

    data = request.get_json(force=True) or {}
    evt = (data.get("type") or "").lower()
    dwell = data.get("dwell_ms") or 0
    device = (data.get("device_id") or "").strip()
    ip = get_ip()

    now = now_utc()

    LAST_SEEN_IP[ip].append(now)
    if device:
        LAST_SEEN_DEVICE[device].append(now)

    geo_data = geo(ip)
    reps = touches(LAST_SEEN_DEVICE[device], SETTINGS["repeat_window_seconds"]) if device else touches(LAST_SEEN_IP[ip], SETTINGS["repeat_window_seconds"])

    # ===============================
    # ✅ 1. Repetición rápida
    # ===============================
    if evt == "land" and reps >= SETTINGS["repeat_required"]:
        mask(device, ip, SETTINGS["daily_soft_mask_hours"])

    # ===============================
    # ✅ 2. Dwell muy rápido
    # ===============================
    if dwell < SETTINGS["fast_dwell_ms"]:
        soft_block(device, ip, SETTINGS["daily_soft_block_hours"])

    # ===============================
    # ✅ 3. Anti-VPN
    # ===============================
    if geo_data["vpn"]:
        mask(device, ip, SETTINGS["vpn_mask_hours"])
        if reps >= 2:
            soft_block(device, ip, SETTINGS["vpn_block_hours"])

    # ===============================
    # ✅ 4. Anti-refresh
    # ===============================
    if evt in ("land", "refresh"):
        recent = touches(LAST_SEEN_DEVICE[device], SETTINGS["refresh_window_seconds"])
        if recent >= SETTINGS["refresh_threshold"]:
            soft_block(device, ip, SETTINGS["refresh_block_hours"])

    # ===============================
    # ✅ 5. Penalización nocturna
    # ===============================
    h = bogota_now().hour
    if 0 <= h < 5 and reps >= 3:
        soft_block(device, ip, SETTINGS["night_block_hours"])

    # ===============================
    # ✅ 6. Detección UA sospechoso
    # ===============================
    ua = (data.get("ua") or "").lower()
    if BOT_UA_PAT.search(ua):
        soft_block(device, ip, 24)

    # Registro del evento
    data["ts"] = now_iso()
    data["ip"] = ip
    data["geo"] = geo_data
    EVENTS.append(data)

    return ("", 204)

# ======================================================
# ✅ PANEL — Ver eventos
# ======================================================
@app.get("/api/events")
def api_events():
    out = list(EVENTS)[-300:]
    out.reverse()
    return jsonify({"events": out})

# ======================================================
# ✅ Bloqueos manuales
# ======================================================
@app.post("/api/blockdevices")
def api_block_device():
    d = request.json.get("device_id")
    BLOCK_DEVICES.add(d)
    return jsonify({"ok": True})

@app.post("/api/blockips")
def api_block_ip():
    ip = request.json.get("ip")
    BLOCK_IPS.add(ip)
    return jsonify({"ok": True})


# ======================================================
# ✅ Run
# ======================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
