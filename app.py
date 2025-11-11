# ======================================================
# 🚨 ClickGuardian PRO — 6 capas anti-clicks basura
# ======================================================
# Capas:
# 1) Repetición < 60s y visitas rápidas (dwell)        -> mask / block
# 2) Abuso diario (3 / 5 / 7+)                          -> mask suave / block 72h / block perm
# 3) Sesión "fantasma": sin scroll/mouse                -> mask / block si reincide
# 4) Anti-VPN/proxy                                     -> mask / block si repite
# 5) Anti-refresh inteligente                           -> mask / block
# 6) Penalización nocturna (00:00–05:00 Bogotá)         -> mask / block

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta, date
from collections import deque, defaultdict
from functools import lru_cache
import requests, re, logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
app = Flask(__name__)

# CORS
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

# =======================
# Estado en memoria
# =======================
EVENTS = deque(maxlen=50000)

BLOCK_DEVICES = set()          # bloqueos permanentes (device)
BLOCK_IPS     = set()          # bloqueos permanentes (ip)

# bloqueos temporales: {id: expire_dt}
SOFT_BLOCK_DEVICES = {}
SOFT_BLOCK_IPS     = {}

MASK_DEVICES = {}              # “capa de engaño”: {device_id: expire_dt}
MASK_IPS     = {}

WHITELIST_DEVICES = set()
WHITELIST_IPS     = set()

LAST_SEEN_DEVICE = defaultdict(deque)  # timestamps de hits recientes
LAST_SEEN_IP     = defaultdict(deque)

DAILY_COUNTER_DEVICE = defaultdict(lambda: defaultdict(int))  # device_id -> {YYYYMMDD: count}
DAILY_COUNTER_IP     = defaultdict(lambda: defaultdict(int))

# =======================
# Parámetros
# =======================
SETTINGS = {
    # repetición
    "repeat_window_seconds": 60,
    "repeat_required": 2,

    # dwell
    "fast_dwell_ms": 800,          # visita "rápida"
    "min_good_dwell_ms": 2000,     # buena visita

    # abuso diario
    "daily_soft_mask": 3,          # 3 visitas/día -> mask 6h
    "daily_soft_mask_hours": 6,
    "daily_soft_block": 5,         # 5 visitas/día -> block 72h
    "daily_soft_block_hours": 72,
    "daily_perm_block": 7,         # 7 visitas/día -> perm block

    # sesión fantasma (sin scroll/mouse)
    "ghost_grace_seconds": 10,     # ventana para detectar interacción
    "ghost_mask_hours": 24,
    "ghost_block_hours": 72,

    # anti-VPN
    "vpn_mask": True,
    "vpn_block_on_repeats": 2,     # 2 repeticiones rápidas con VPN -> block 72h
    "vpn_block_hours": 72,

    # anti-refresh
    "refresh_window_seconds": 90,
    "refresh_threshold": 3,        # 3 land/refresh sin leave/scroll -> sanción
    "refresh_mask_hours": 12,
    "refresh_block_hours": 48,

    # horario nocturno Bogotá
    "night_start_hour": 0,         # 00:00
    "night_end_hour": 5,           # 05:00
    "night_repeat_to_block": 3,    # 3 entradas nocturnas -> block 24h
    "night_block_hours": 24,

    # riesgo UA/ads
    "risk_autoblock": True,
    "risk_threshold": 80,
}

BOT_UA_PAT = re.compile(
    r"bot|crawler|spider|preview|scan|archiver|linkchecker|monitor|pingdom|ahrefs|semrush|curl|wget|headless",
    re.I
)

# =======================
# Helpers
# =======================
def now_utc():
    return datetime.now(timezone.utc)

def now_iso():
    return now_utc().isoformat()

def bogota_now():
    # Bogotá UTC-5 (sin DST). Suficiente para reglas nocturnas.
    return now_utc() + timedelta(hours=-5)

def yyyymmdd(dt: datetime):
    b = bogota_now() if dt.tzinfo else dt
    return b.strftime("%Y%m%d")

def prune_expired(dct: dict):
    to_del = [k for k, exp in dct.items() if exp <= now_utc()]
    for k in to_del:
        del dct[k]

def get_client_ip():
    h = request.headers
    for k in ("CF-Connecting-IP","True-Client-IP","X-Real-IP"):
        v = h.get(k)
        if v:
            return v.strip()
    xff = h.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr

@lru_cache(maxsize=20000)
def geo_lookup(ip: str):
    try:
        if not ip or ip.startswith(("127.","10.","192.168.","::1")):
            return {"country":"LOCAL","region":"-","city":"-","isp":"LAN","asn":"-","lat":0,"lon":0,"vpn":False}
        r = requests.get(f"https://ipwho.is/{ip}", timeout=3)
        j = r.json() if r.ok else {}
        conn = j.get("connection",{}) or {}
        sec = j.get("security",{}) or {}
        return {
            "country": j.get("country","-"),
            "region":  j.get("region","-"),
            "city":    j.get("city","-"),
            "isp":     conn.get("isp") or j.get("org","-"),
            "asn":     conn.get("asn","-"),
            "lat":     j.get("latitude",0),
            "lon":     j.get("longitude",0),
            "vpn":     bool(sec.get("vpn",False))
        }
    except Exception:
        return {"country":"-","region":"-","city":"-","isp":"-","asn":"-","lat":0,"lon":0,"vpn":False}

def _prune_window(dq: deque, cutoff: datetime):
    while dq and dq[0] < cutoff:
        dq.popleft()

def touches_in_window(dq: deque, seconds: int) -> int:
    cutoff = now_utc() - timedelta(seconds=seconds)
    _prune_window(dq, cutoff)
    return len(dq)

def touches_device(device_id: str, seconds: int) -> int:
    return touches_in_window(LAST_SEEN_DEVICE[device_id], seconds)

def touches_ip(ip: str, seconds: int) -> int:
    return touches_in_window(LAST_SEEN_IP[ip], seconds)

def incr_daily(counter_map, key):
    today = yyyymmdd(now_utc())
    counter_map[key][today] += 1
    return counter_map[key][today]

def get_daily(counter_map, key):
    today = yyyymmdd(now_utc())
    return counter_map[key][today]

def mark_event(ev: dict):
    EVENTS.append(ev)

def compute_risk(ev: dict):
    score = 0
    reasons = []

    evt_type = (ev.get("type") or "").lower()
    dwell = ev.get("dwell_ms") or 0
    ua = (ev.get("ua") or "").lower()
    ref = (ev.get("ref") or "")
    url = (ev.get("url") or "")
    geo = ev.get("geo") or {}

    if dwell and dwell < SETTINGS["fast_dwell_ms"]:
        score += 30; reasons.append("Dwell rápido")

    if BOT_UA_PAT.search(ua):
        score += 25; reasons.append("UA sospechosa")

    if ("google" in ref or "gclid=" in url) and "gclid=" not in url:
        score += 25; reasons.append("Ads ref sin gclid")

    if geo.get("country") not in ("LOCAL","Colombia","CO",None):
        score += 10; reasons.append("País ≠ CO")

    if geo.get("vpn"):
        score += 15; reasons.append("VPN detectada")

    if evt_type == "whatsapp_click":
        score = max(0, score - 30); reasons.append("Click WhatsApp (mitiga)")

    score = max(0, min(100, score))
    return {"score": score, "suspicious": score >= SETTINGS["risk_threshold"], "reasons": reasons}

def is_night_bogota():
    h = bogota_now().hour
    s, e = SETTINGS["night_start_hour"], SETTINGS["night_end_hour"]
    return s <= h < e

def has_interaction_after_land(device_id: str, land_ts_iso: str, within_sec: int) -> bool:
    """Busca eventos scroll/mousemove/click tras land en ventana within_sec."""
    if not device_id or not land_ts_iso:
        return False
    try:
        land_ts = datetime.fromisoformat(land_ts_iso)
    except Exception:
        return False

    limit = land_ts + timedelta(seconds=within_sec)
    for ev in reversed(EVENTS):
        if ev.get("device_id") != device_id:
            continue
        t = ev.get("ts")
        if not t:
            continue
        try:
            ts = datetime.fromisoformat(t)
        except Exception:
            continue
        if ts < land_ts:
            break
        if ts > limit:
            continue
        if (ev.get("type") or "").lower() in ("scroll","mousemove","interaction","click"):
            return True
    return False

def count_recent_lands_no_leave(device_id: str, seconds: int) -> int:
    """Cuenta 'land' recientes sin 'leave' intermedio (para detectar refresh)."""
    if not device_id:
        return 0
    cutoff = now_utc() - timedelta(seconds=seconds)
    lands = 0
    for ev in reversed(EVENTS):
        if ev.get("device_id") != device_id:
            continue
        try:
            ts = datetime.fromisoformat(ev.get("ts"))
        except Exception:
            continue
        if ts < cutoff:
            break
        typ = (ev.get("type") or "").lower()
        if typ == "leave":
            break  # rompemos la racha
        if typ in ("land","refresh"):
            lands += 1
    return lands

def apply_mask_for(hours: int, device_id: str = None, ip: str = None):
    exp = now_utc() + timedelta(hours=hours)
    if device_id:
        MASK_DEVICES[device_id] = exp
    if ip:
        MASK_IPS[ip] = exp

def soft_block_for(hours: int, device_id: str = None, ip: str = None):
    exp = now_utc() + timedelta(hours=hours)
    if device_id:
        SOFT_BLOCK_DEVICES[device_id] = exp
    if ip:
        SOFT_BLOCK_IPS[ip] = exp

# =======================
# Rutas UI
# =======================
@app.route("/")
def home():
    return render_template("index.html")

# =======================
# GUARD
# =======================
@app.post("/guard")
def guard():
    # Limpia expirados
    prune_expired(SOFT_BLOCK_DEVICES); prune_expired(SOFT_BLOCK_IPS)
    prune_expired(MASK_DEVICES); prune_expired(MASK_IPS)

    data = request.get_json(force=True, silent=True) or {}
    device_id = (data.get("device_id") or "").strip()
    ip = get_client_ip()

    # Whitelist
    if device_id in WHITELIST_DEVICES or ip in WHITELIST_IPS:
        return jsonify({"blocked": False, "by": "whitelist"})

    # Permanente
    if device_id and device_id in BLOCK_DEVICES:
        return jsonify({"blocked": True, "by": "device"}), 403
    if ip in BLOCK_IPS:
        return jsonify({"blocked": True, "by": "ip"}), 403

    # Temporales
    if device_id and device_id in SOFT_BLOCK_DEVICES:
        return jsonify({"blocked": True, "by": "device_soft"}), 403
    if ip in SOFT_BLOCK_IPS:
        return jsonify({"blocked": True, "by": "ip_soft"}), 403

    # Mask (capa de engaño)
    if device_id in MASK_DEVICES or ip in MASK_IPS:
        return jsonify({"blocked": False, "mask": True})

    # OK
    return jsonify({"blocked": False})

# =======================
# TRACK
# =======================
@app.route("/track", methods=["POST","OPTIONS"])
def track():
    if request.method == "OPTIONS":
        return ("", 204)

    # Limpia expirados
    prune_expired(SOFT_BLOCK_DEVICES); prune_expired(SOFT_BLOCK_IPS)
    prune_expired(MASK_DEVICES); prune_expired(MASK_IPS)

    data = request.get_json(force=True, silent=True) or {}
    ip = get_client_ip()
    device_id = (data.get("device_id") or "").strip() or None
    evt_type = (data.get("type") or "").lower()
    dwell = data.get("dwell_ms") or 0
    ua = data.get("ua") or ""
    url = data.get("url") or ""
    ref = data.get("ref") or ""

    now = now_utc()
    LAST_SEEN_IP[ip].append(now)
    if device_id:
        LAST_SEEN_DEVICE[device_id].append(now)

    # Enriquecer
    data["ip"] = ip
    data["device_id"] = device_id
    data["ts"] = now_iso()
    data["geo"] = geo_lookup(ip)
    data["risk"] = compute_risk({
        "type": evt_type, "dwell_ms": dwell, "ua": ua, "ref": ref, "url": url, "geo": data["geo"]
    })

    # Contadores diarios
    if evt_type in ("land", "refresh"):
        if device_id:
            daily = incr_daily(DAILY_COUNTER_DEVICE, device_id)
        else:
            daily = incr_daily(DAILY_COUNTER_IP, ip)
    else:
        daily = None

    # ============================
    # Reglas de decisión (mask/block)
    # ============================
    # Si está en whitelist, no aplicar sanción
    if (device_id and device_id in WHITELIST_DEVICES) or (ip in WHITELIST_IPS):
        data["action"] = "allow_whitelist"
        mark_event(data)
        return ("", 204)

    # Atajos si ya está sancionado
    if (device_id and device_id in BLOCK_DEVICES) or (ip in BLOCK_IPS):
        data["action"] = "blocked_perm"
        mark_event(data)
        return ("", 204)
    if (device_id and device_id in SOFT_BLOCK_DEVICES) or (ip in SOFT_BLOCK_IPS):
        data["action"] = "blocked_soft"
        mark_event(data)
        return ("", 204)

    masked_now = False
    block_now = False
    reasons = []

    # (1) Repetición en ventana corta
    reps = touches_device(device_id, SETTINGS["repeat_window_seconds"]) if device_id else touches_ip(ip, SETTINGS["repeat_window_seconds"])
    if evt_type in ("land","refresh") and reps >= SETTINGS["repeat_required"]:
        # primero máscara, si reincide luego bloqueo
        apply_mask_for(SETTINGS["daily_soft_mask_hours"], device_id, ip)
        masked_now = True
        reasons.append("repeat_window_mask")

    # (2) Visitas rápidas + repeticiones rápidas
    if dwell and dwell < SETTINGS["fast_dwell_ms"]:
        if reps >= SETTINGS["repeat_required"]:
            soft_block_for(SETTINGS["daily_soft_block_hours"], device_id, ip)
            block_now = True
            reasons.append("fast_repeats_block")
        else:
            apply_mask_for(SETTINGS["ghost_mask_hours"], device_id, ip)
            masked_now = True
            reasons.append("fast_visit_mask")

    # (3) Sesión fantasma: sin scroll/mouse tras land
    if evt_type == "land":
        land_ts = data["ts"]
        # deferimos la decisión: anotamos y en el siguiente hit se evalúa,
        # o el front nos enviará "ghost_check" si no hubo interacción.
        pass
    elif evt_type in ("ghost_check",):
        # front emite ghost_check 10s después del land si no vio scroll/mouse
        apply_mask_for(SETTINGS["ghost_mask_hours"], device_id, ip)
        masked_now = True
        reasons.append("ghost_session_mask")

    # (4) Anti-VPN
    if data["geo"].get("vpn"):
        if SETTINGS["vpn_mask"] and not masked_now:
            apply_mask_for(SETTINGS["daily_soft_mask_hours"], device_id, ip)
            masked_now = True
            reasons.append("vpn_mask")
        if reps >= SETTINGS["vpn_block_on_repeats"]:
            soft_block_for(SETTINGS["vpn_block_hours"], device_id, ip)
            block_now = True
            reasons.append("vpn_repeats_block")

    # (5) Anti-refresh
    if evt_type in ("land","refresh"):
        recent_lands = count_recent_lands_no_leave(device_id, SETTINGS["refresh_window_seconds"]) if device_id else 0
        if recent_lands >= SETTINGS["refresh_threshold"]:
            # si no hay scroll en esa racha, sancionamos más
            interacted = has_interaction_after_land(device_id, data["ts"], SETTINGS["ghost_grace_seconds"])
            if not interacted:
                soft_block_for(SETTINGS["refresh_block_hours"], device_id, ip)
                block_now = True
                reasons.append("refresh_block")
            else:
                apply_mask_for(SETTINGS["refresh_mask_hours"], device_id, ip)
                masked_now = True
                reasons.append("refresh_mask")

    # (6) Penalización nocturna
    if evt_type in ("land","refresh") and is_night_bogota():
        nightly_reps = touches_device(device_id, SETTINGS["repeat_window_seconds"]) if device_id else 0
        if nightly_reps >= SETTINGS["night_repeat_to_block"]:
            soft_block_for(SETTINGS["night_block_hours"], device_id, ip)
            block_now = True
            reasons.append("night_block")

    # (7) Abuso diario
    if daily is not None:
        if daily >= SETTINGS["daily_perm_block"]:
            if device_id: BLOCK_DEVICES.add(device_id)
            else: BLOCK_IPS.add(ip)
            block_now = True
            reasons.append("daily_perm_block")
        elif daily >= SETTINGS["daily_soft_block"]:
            soft_block_for(SETTINGS["daily_soft_block_hours"], device_id, ip)
            block_now = True
            reasons.append("daily_soft_block")
        elif daily >= SETTINGS["daily_soft_mask"] and not masked_now and not block_now:
            apply_mask_for(SETTINGS["daily_soft_mask_hours"], device_id, ip)
            masked_now = True
            reasons.append("daily_soft_mask")

    # (8) Riesgo global por UA/ads
    if SETTINGS["risk_autoblock"] and data["risk"]["score"] >= SETTINGS["risk_threshold"] and not block_now:
        apply_mask_for(SETTINGS["daily_soft_mask_hours"], device_id, ip)
        masked_now = True
        reasons.append("risk_mask")

    # Marcar acción tomada
    if block_now:
        data["action"] = "blocked"
    elif masked_now:
        data["action"] = "masked"
    else:
        data["action"] = "allowed"

    data["reasons"] = reasons
    mark_event(data)
    return ("", 204)

# =======================
# APIs de inspección
# =======================
@app.get("/api/events")
def api_events():
    limit = int(request.args.get("limit", 200))
    evs = list(EVENTS)[-limit:]
    evs.reverse()
    out = []
    for ev in evs:
        device_id = ev.get("device_id")
        ip = ev.get("ip")
        blocked_perm = (device_id in BLOCK_DEVICES) or (ip in BLOCK_IPS)
        blocked_soft = (device_id in SOFT_BLOCK_DEVICES) or (ip in SOFT_BLOCK_IPS)
        masked = (device_id in MASK_DEVICES) or (ip in MASK_IPS)
        out.append({
            **ev,
            "blocked_perm": blocked_perm,
            "blocked_soft": blocked_soft,
            "masked": masked
        })
    return jsonify({"events": out})

@app.get("/api/blocklist")
def get_blocklist():
    prune_expired(SOFT_BLOCK_DEVICES); prune_expired(SOFT_BLOCK_IPS)
    prune_expired(MASK_DEVICES); prune_expired(MASK_IPS)
    return jsonify({
        "perm_devices": list(BLOCK_DEVICES),
        "perm_ips": list(BLOCK_IPS),
        "soft_devices": {k: v.isoformat() for k, v in SOFT_BLOCK_DEVICES.items()},
        "soft_ips": {k: v.isoformat() for k, v in SOFT_BLOCK_IPS.items()},
        "mask_devices": {k: v.isoformat() for k, v in MASK_DEVICES.items()},
        "mask_ips": {k: v.isoformat() for k, v in MASK_IPS.items()},
        "whitelist_devices": list(WHITELIST_DEVICES),
        "whitelist_ips": list(WHITELIST_IPS),
        "settings": SETTINGS
    })

@app.post("/api/blockdevices")
def add_block_device():
    data = request.get_json(force=True) or {}
    d = (data.get("device_id") or "").strip()
    if not d:
        return jsonify({"ok": False, "error": "device_id requerido"}), 400
    BLOCK_DEVICES.add(d)
    return jsonify({"ok": True, "blocked": d})

@app.post("/api/blockips")
def add_block_ip():
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "ip requerida"}), 400
    BLOCK_IPS.add(ip)
    return jsonify({"ok": True, "blocked": ip})

@app.delete("/api/blockdevices")
def del_block_device():
    data = request.get_json(force=True) or {}
    d = (data.get("device_id") or "").strip()
    if d in BLOCK_DEVICES:
        BLOCK_DEVICES.remove(d)
        return jsonify({"ok": True, "unblocked": d})
    return jsonify({"ok": False, "error": "device_id no encontrado"}), 404

@app.delete("/api/blockips")
def del_block_ip():
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if ip in BLOCK_IPS:
        BLOCK_IPS.remove(ip)
        return jsonify({"ok": True, "unblocked": ip})
    return jsonify({"ok": False, "error": "ip no encontrada"}), 404

@app.post("/api/whitelist/devices")
def add_whitelist_device():
    data = request.get_json(force=True) or {}
    d = (data.get("device_id") or "").strip()
    if not d:
        return jsonify({"ok": False, "error": "device_id requerido"}), 400
    WHITELIST_DEVICES.add(d)
    return jsonify({"ok": True, "added": d})

@app.delete("/api/whitelist/devices")
def del_whitelist_device():
    data = request.get_json(force=True) or {}
    d = (data.get("device_id") or "").strip()
    if d in WHITELIST_DEVICES:
        WHITELIST_DEVICES.remove(d)
        return jsonify({"ok": True, "removed": d})
    return jsonify({"ok": False, "error": "device_id no encontrado"}), 404

@app.get("/api/settings")
def get_settings():
    return jsonify(SETTINGS)

@app.post("/api/settings")
def set_settings():
    data = request.get_json(force=True) or {}
    for k in list(SETTINGS.keys()):
        if k in data:
            SETTINGS[k] = data[k]
    return jsonify({"ok": True, "settings": SETTINGS})

# =======================
# Run
# =======================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
