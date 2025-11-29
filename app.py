# ======================================================
# ✅ ClickGuardian — versión estable funcional
# ======================================================

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from functools import lru_cache
import requests, re, logging

import json, os

STORAGE_FILE = "storage.json"

def load_storage():
    if not os.path.exists(STORAGE_FILE):
        return

    try:
        with open(STORAGE_FILE, "r") as f:
            data = json.load(f)

        # Restaurar todo
        BLOCK_DEVICES.update(data.get("block_devices", []))
        BLOCK_IPS.update(data.get("block_ips", []))
        WHITELIST_DEVICES.update(data.get("whitelist_devices", []))
        WHITELIST_IPS.update(data.get("whitelist_ips", []))

        # Restauramos settings si existen
        saved_settings = data.get("settings", {})
        for k, v in saved_settings.items():
            if k in SETTINGS:
                SETTINGS[k] = v

        logging.info("🔄 Storage cargado exitosamente")

    except Exception as e:
        logging.error(f"❌ Error cargando storage: {e}")


def save_storage():
    try:
        data = {
            "block_devices": list(BLOCK_DEVICES),
            "block_ips": list(BLOCK_IPS),
            "whitelist_devices": list(WHITELIST_DEVICES),
            "whitelist_ips": list(WHITELIST_IPS),
            "settings": SETTINGS
        }
        with open(STORAGE_FILE, "w") as f:
            json.dump(data, f, indent=2)

        logging.info("💾 Storage guardado exitosamente")

    except Exception as e:
        logging.error(f"❌ Error guardando storage: {e}")


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
app = Flask(__name__)

# ✅ CORS
CORS(app, resources={
    r"/track": {"origins": [
        "https://medigoencas.com",
        "https://www.medigoencas.com",
        "https://sumedicoencasa.com",
        "https://www.sumedicoencasa.com",
        "https://asisvitalips.com",
        "https://www.asisvitalips.com",
        "https://clikguardian.onrender.com",
        "http://localhost",
        "http://127.0.0.1"
    ]},
    r"/api/*": {"origins": "*"},
    r"/guard": {"origins": "*"}
})

# ✅ Estado global
EVENTS = deque(maxlen=30000)

BLOCK_DEVICES = set()
BLOCK_IPS     = set()

WHITELIST_DEVICES = set()
WHITELIST_IPS     = set()

LAST_SEEN_DEVICE = defaultdict(deque)
LAST_SEEN_IP     = defaultdict(deque)

SETTINGS = {
    "risk_autoblock": True,
    "risk_threshold": 80,
    "repeat_window_seconds": 60,
    "repeat_window_min": 60,
    "repeat_required": 2,
    "fast_dwell_ms": 600,
    "fast_repeat_required": 3,
    "min_good_dwell_ms": 2000,
    "good_dwell_window_minutes": 5
}

BOT_UA_PAT = re.compile(
    r"bot|crawler|spider|preview|scan|archiver|linkchecker|monitor|pingdom|ahrefs|semrush|curl|wget",
    re.I
)

# ✅ Helpers
def now_iso():
    return datetime.now(timezone.utc).isoformat()

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
    """Geo Lookup Inteligente con 3 APIs + fusión de ciudad más probable"""

    # 🔥 1. Localhost o redes internas
    if not ip or ip.startswith(("127.", "10.", "192.168.", "::1")):
        return {
            "country": "LOCAL",
            "region": "-",
            "city": "Local",
            "district": "-",
            "isp": "LAN",
            "asn": "-",
            "lat": 0,
            "lon": 0,
            "vpn": False
        }

    results = []

    # ================================
    # API 1 → ipwho.is
    # ================================
    try:
        r1 = requests.get(f"https://ipwho.is/{ip}", timeout=2).json()
        results.append({
            "city": r1.get("city"),
            "region": r1.get("region"),
            "country": r1.get("country"),
            "isp": (r1.get("connection") or {}).get("isp") or r1.get("org"),
            "asn": (r1.get("connection") or {}).get("asn"),
            "lat": r1.get("latitude"),
            "lon": r1.get("longitude"),
            "vpn": (r1.get("security") or {}).get("vpn", False)
        })
    except:
        pass

    # ================================
    # API 2 → ipapi.co
    # ================================
    try:
        r2 = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2).json()
        results.append({
            "city": r2.get("city"),
            "region": r2.get("region"),
            "country": r2.get("country_name"),
            "isp": r2.get("org"),
            "asn": r2.get("asn"),
            "lat": r2.get("latitude"),
            "lon": r2.get("longitude"),
            "vpn": False  # ipapi no devuelve vpn
        })
    except:
        pass

    # ================================
    # API 3 → ipinfo.io  (sin token usa datos libres)
    # ================================
    try:
        r3 = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2).json()
        loc = (r3.get("loc") or "0,0").split(",")

        results.append({
            "city": r3.get("city"),
            "region": r3.get("region"),
            "country": r3.get("country"),
            "isp": r3.get("org"),
            "asn": None,
            "lat": float(loc[0]),
            "lon": float(loc[1]),
            "vpn": False
        })
    except:
        pass

    # ================================
    # Si todas fallan
    # ================================
    if not results:
        return {
            "city": "-",
            "region": "-",
            "country": "-",
            "isp": "-",
            "asn": "-",
            "lat": 0,
            "lon": 0,
            "vpn": False
        }

    # ================================
    # FUSIÓN INTELIGENTE
    # Elegir ciudad más repetida (o la que no sea None)
    # ================================
    def most_common(field):
        vals = [r.get(field) for r in results if r.get(field)]
        if not vals:
            return "-"
        return max(set(vals), key=vals.count)

    fused = {
        "city": most_common("city"),
        "region": most_common("region"),
        "country": most_common("country"),
        "isp": most_common("isp"),
        "asn": most_common("asn"),
        "lat": most_common("lat"),
        "lon": most_common("lon"),
        "vpn": any([r.get("vpn") for r in results])
    }

    return fused

def _prune_window(dq: deque, cutoff: datetime):
    while dq and dq[0] < cutoff:
        dq.popleft()

def count_recent(dq: deque, seconds: int) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    _prune_window(dq, cutoff)
    return len(dq)

def touches_in_window_device(device_id: str, seconds: int):
    return count_recent(LAST_SEEN_DEVICE[device_id], seconds)

def touches_in_window_ip(ip: str, seconds: int):
    return count_recent(LAST_SEEN_IP[ip], seconds)

def had_good_dwell_recently(device_id: str, minutes: int, min_ms: int) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

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

def compute_risk(ev: dict):
    score = 0
    reasons = []

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
    if geo.get("country") not in ("LOCAL","Colombia","CO",None):
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

@app.route("/guard", methods=["POST", "OPTIONS"])
def guard_check():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    device_id = (data.get("device_id") or "").strip()
    ip = get_client_ip()

    # 🔥 1. Si está en whitelist → permitir siempre
    if device_id in WHITELIST_DEVICES or ip in WHITELIST_IPS:
        return jsonify({"ok": True, "allowed": True})

    # 🔥 2. Si está bloqueado → devolver 403
    if device_id in BLOCK_DEVICES or ip in BLOCK_IPS:
        return ("", 403)

    # 🔥 3. Si no está bloqueado → permitir
    return jsonify({"ok": True, "allowed": True})

# ✅ UI
@app.route("/")
def home():
    return render_template("index.html")

# ✅ TRACK
@app.route("/track", methods=["POST","OPTIONS"])
def track():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}

    ip = get_client_ip()
    device_id = (data.get("device_id") or "").strip() or None

    now = datetime.now(timezone.utc)
    LAST_SEEN_IP[ip].append(now)
    if device_id:
        LAST_SEEN_DEVICE[device_id].append(now)

    data["ip"] = ip
    data["device_id"] = device_id
    data["ts"] = now_iso()
    data["geo"] = geo_lookup(ip)
    data["risk"] = compute_risk(data)

    repeats = touches_in_window_device(device_id, SETTINGS["repeat_window_seconds"]) if device_id else touches_in_window_ip(ip, SETTINGS["repeat_window_seconds"])
    dwell = data.get("dwell_ms") or 0
    evt_type = (data.get("type") or "").lower()

    if device_id in WHITELIST_DEVICES or ip in WHITELIST_IPS:
        data["blocked"] = False
        EVENTS.append(data)
        return ("", 204)

    autoblock = False
    reason_ab = None

    if SETTINGS["risk_autoblock"] and data["risk"]["score"] >= SETTINGS["risk_threshold"]:
        autoblock = True
        reason_ab = "risk"

    if evt_type == "whatsapp_click" and repeats >= SETTINGS["repeat_required"]:
        if not had_good_dwell_recently(device_id, SETTINGS["good_dwell_window_minutes"], SETTINGS["min_good_dwell_ms"]):
            autoblock = True
            reason_ab = "wa_repeats"

    if dwell < SETTINGS["fast_dwell_ms"] and repeats >= SETTINGS["fast_repeat_required"]:
        autoblock = True
        reason_ab = "fast_repeats"

    if autoblock:
        if device_id:
            BLOCK_DEVICES.add(device_id)
            data["autoblocked"] = {"by": "device", "reason": reason_ab}
        else:
            BLOCK_IPS.add(ip)
            data["autoblocked"] = {"by": "ip", "reason": reason_ab}

        # 🔥🔥 GUARDAR EN DISCO inmediatamente
        save_storage()

    else:
        data["autoblocked"] = False

    data["blocked"] = (device_id in BLOCK_DEVICES) or (ip in BLOCK_IPS)
    EVENTS.append(data)

    return ("", 204)

# ✅ APIs
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
        out.append({
            **ev,
            "blocked_now": blocked_device or blocked_ip,
            "blocked_by": "device" if blocked_device else ("ip" if blocked_ip else None)
        })

    return jsonify({"events": out})

@app.get("/api/blocklist")
def get_blocklist():
    return jsonify({
        "devices": list(BLOCK_DEVICES),
        "ips": list(BLOCK_IPS),
        "whitelist_devices": list(WHITELIST_DEVICES),
        "whitelist_ips": list(WHITELIST_IPS),
    })

@app.post("/api/blockdevices")
def add_block_device():
    data = request.get_json(force=True) or {}
    d = (data.get("device_id") or "").strip()
    if not d:
        return jsonify({"ok": False, "error": "device_id requerido"}), 400
    BLOCK_DEVICES.add(d)
    save_storage()
    return jsonify({"ok": True, "blocked": d})


@app.post("/api/blockips")
def add_block_ip():
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "ip requerida"}), 400
    BLOCK_IPS.add(ip)
    save_storage()
    return jsonify({"ok": True, "blocked": ip})


@app.delete("/api/blockdevices")
def del_block_device():
    data = request.get_json(force=True) or {}
    d = (data.get("device_id") or "").strip()
    if d in BLOCK_DEVICES:
        BLOCK_DEVICES.remove(d)
        save_storage()
        return jsonify({"ok": True, "unblocked": d})


@app.delete("/api/blockips")
def del_block_ip():
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if ip in BLOCK_IPS:
        BLOCK_IPS.remove(ip)
        save_storage()
        return jsonify({"ok": True, "unblocked": ip})

@app.delete("/api/whitelist/devices")
def delete_whitelist_device():
    data = request.get_json(force=True) or {}
    d = (data.get("device_id") or "").strip()

    if d in WHITELIST_DEVICES:
        WHITELIST_DEVICES.remove(d)
        save_storage()
        return jsonify({"ok": True, "removed": d})

    return jsonify({"ok": False, "error": "device_id no encontrado"}), 404


@app.get("/api/settings")
def get_settings():
    return jsonify(SETTINGS)

@app.post("/api/settings")
def set_settings():
    data = request.get_json(force=True) or {}
    allowed = SETTINGS.keys()
    for k in allowed:
        if k in data:
            SETTINGS[k] = data[k]
    save_storage()
    return jsonify({"ok": True, "settings": SETTINGS})


# Cargar memoria persistente
load_storage()

# ✅ Run
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
