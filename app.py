# ======================================================
# ✅ ClickGuardian — versión estable funcional
# ======================================================

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from functools import lru_cache
import requests, re, logging
from ipaddress import ip_network, ip_address
from google.ads.googleads.client import GoogleAdsClient
from google.ads.googleads.errors import GoogleAdsException
import json, os



import hashlib


def get_account_for_domain(domain: str):
    domain = domain.lower()
    if "medigo" in domain:
        return "7730048070"     # MediGo
    if "sumedico" in domain:
        return "9618914395"     # Su Médico
    return "7730048070"         # Default

HIGH_RISK_KEYWORDS = {
    "urgencias médicas",
    "urgencias medicas",
    "médico 24 horas",
    "medico 24 horas",
    "urgencias médicas domicilio",
    "urgencias medicas domicilio",
    "doctor urgente",
    "doctor a domicilio urgente"
}


STORAGE_FILE = "storage.json"

KNOWN_DATACENTERS = [
    "aws", "amazon", "google cloud", "gcp", "azure",
    "microsoft", "ovh", "digitalocean", "contabo",
    "vultr", "linode", "hetzner"
]


def load_storage():
    if not os.path.exists(STORAGE_FILE):
        return

    try:
        with open(STORAGE_FILE, "r") as f:
            data = json.load(f)

        # Restaurar todo
        BLOCK_DEVICES.update(data.get("block_devices", []))
        BLOCK_IPS.update(data.get("block_ips", []))
        BLOCK_RANGES.update(data.get("block_ranges", []))
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
            "block_ranges": list(BLOCK_RANGES),
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

# ✅ CORS — versión FINAL (incluye /track, /guard, /api/events)


allowed_origins = [
    "https://medigoencas.com",
    "https://www.medigoencas.com",
    "https://sumedicoencasa.com",
    "https://www.sumedicoencasa.com",
    "https://asisvitalips.com",
    "https://www.asisvitalips.com",
    "https://clikguardian.onrender.com",
    "http://localhost",
    "http://127.0.0.1"
]
CORS(app,
     resources={r"/*": {"origins": allowed_origins}},
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"])


# ✅ Estado global

EVENTS = deque(maxlen=30000)

BLOCK_DEVICES = set()
BLOCK_IPS     = set()
BLOCK_RANGES  = set()

WHITELIST_DEVICES = set()
WHITELIST_IPS     = set()

LAST_SEEN_DEVICE = defaultdict(deque)
LAST_SEEN_IP     = defaultdict(deque)

LAST_DWELL_DEVICE = {}
LAST_DWELL_IP     = {}


SETTINGS = {
    "risk_autoblock": True,
    "risk_threshold": 85,         # antes tenías 75
    "repeat_window_seconds": 60,  # antes 45
    "repeat_required": 4,         # antes 2
    "fast_dwell_ms": 350,         # antes 450 (ok)
    "fast_repeat_required": 6,    # antes 3 (subo a 6)
    "min_good_dwell_ms": 2200,    # era 2000 (normal)
    "good_dwell_window_minutes": 8 # era 5 (subo)
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

def is_ip_in_blocked_range(ip: str):
    try:
        ip_obj = ip_address(ip)
        for r in BLOCK_RANGES:
            if ip_obj in ip_network(r):
                return True
    except:
        pass
    return False

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

    # ============================
    # ⏱️ Regla 1 — Dwell bajo
    # ============================
    if evt_type != "whatsapp_click" and dwell and dwell < 800:
        score += 30
        reasons.append("Dwell < 800ms")

    # ============================
    # 🤖 Regla 2 — User Agent sospechoso
    # ============================
    ua = (ev.get("ua") or "").lower()
    if BOT_UA_PAT.search(ua):
        score += 25
        reasons.append("UA sospechosa")

    # ============================
    # 📌 Regla 3 — Ads sin gclid
    # ============================
    ref = (ev.get("ref") or "")
    url = (ev.get("url") or "")
    if ("google" in ref or "gclid=" in url) and "gclid=" not in url:
        score += 25
        reasons.append("Ads ref sin gclid")

    # ============================
    # 🌎 Regla 4 — País ≠ CO (CORREGIDO)
    # ============================
    geo = ev.get("geo") or {}
    country = (geo.get("country") or "").lower().strip()

    if country not in ("colombia", "co", "local"):
        score += 10
        reasons.append("País ≠ CO")

    # ============================
    # 🛡️ Regla 5 — VPN
    # ============================
    if geo.get("vpn"):
        score += 15
        reasons.append("VPN detectada")

    # ============================
    # 📱 Regla 6 — Dwell repetido (CORREGIDO: 80 → 20)
    # ============================
    last_dev = ev.get("last_dwell_device")
    last_ip = ev.get("last_dwell_ip")

    if dwell and last_dev and abs(dwell - last_dev) < 20:
        score += 20
        reasons.append("Dwell casi idéntico por device")

    if dwell and (not last_dev) and last_ip and abs(dwell - last_ip) < 20:
        score += 15
        reasons.append("Dwell casi idéntico por IP")

    # ============================
    # 🏢 Regla 7 — ISP Datacenter
    # ============================
    isp = (geo.get("isp") or "").lower()
    if isp and any(dc in isp for dc in KNOWN_DATACENTERS):
        score += 40
        reasons.append("ISP datacenter/proxy sospechoso")

    # ============================
    # 📞 Regla 8 — WhatsApp mitiga
    # ============================
    if evt_type == "whatsapp_click":
        score = max(0, score - 30)
        reasons.append("Click en WhatsApp (mitiga)")

    # ==========================================
    # 🎯 SENSIBILIDAD POR PALABRA CLAVE
    # ==========================================
    keyword = (ev.get("keyword") or "").lower().strip()
    if keyword in HIGH_RISK_KEYWORDS:
        threshold = 60
    else:
        threshold = SETTINGS["risk_threshold"]

    # ============================
    # 🆕 VPN por TZ y resolución (CORREGIDO)
    # ============================
    tz = (ev.get("tz") or "").strip()
    screen = (ev.get("screen") or "")
    lang = (ev.get("lang") or "")

    # Colombia = UTC-5
    if country in ("colombia", "co"):
        if tz not in ("-05:00", "utc-5", "utc−5", "america/bogota"):
            score += 20
            reasons.append("TZ no coincide con CO (VPN probable)")

    # patrón típico de VPN
    if screen and "1536" in screen and "vpn" in ua:
        score += 10
        reasons.append("Patrón de resolución usada en VPN")

    # ============================
    # Resultado final
    # ============================
    score = max(0, min(100, score))

    return {
        "score": score,
        "suspicious": score >= threshold,
        "threshold_used": threshold,
        "reasons": reasons
    }


@app.route("/guard", methods=["POST", "OPTIONS"])
def guard_check():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    device_id = (data.get("device_id") or "").strip()
    ip = get_client_ip()

    if device_id in WHITELIST_DEVICES or ip in WHITELIST_IPS:
        return jsonify({"ok": True, "allowed": True})

    if device_id in BLOCK_DEVICES or ip in BLOCK_IPS or is_ip_in_blocked_range(ip):
        return ("", 403)

    # 🔥 3. Si no está bloqueado → permitir
    return jsonify({"ok": True, "allowed": True})

# ✅ UI
@app.route("/")
def home():
    return render_template("index.html")

def push_ip_to_google_ads(ip: str, domain: str = ""):
    """
    Bloquea una IP dentro de la cuenta Google Ads correcta
    (solo funciona si Google aprueba tu developer_token).
    """
    try:
        customer_id = get_account_for_domain(domain)

        # Cargar Google Ads client
        client = GoogleAdsClient.load_from_storage(
            "/root/clikguardian/google-ads.yaml"
        )

        customer_service = client.get_service("CustomerService")

        # Construir operación
        op = client.get_type("CustomerOperation")
        op.update.resource_name = customer_service.customer_path(customer_id)
        op.update.excluded_ips.append(ip)

        # Máscara requerida
        fm = client.get_type("FieldMask")
        fm.paths.append("excluded_ips")
        op.update_mask.CopyFrom(fm)

        # Enviar
        customer_service.mutate_customer(
            customer_id=customer_id,
            operation=op
        )

        logging.info(f"✅ IP {ip} bloqueada en Google Ads ({customer_id})")

    except Exception as e:
        logging.error(f"❌ Error bloqueando IP en Google Ads: {e}")

@app.route("/track", methods=["POST", "OPTIONS"])
def track():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}

    ip = get_client_ip()

    # ------------------------------------------------------
    # 🔥 DeviceID generado en frontend (localStorage + cookie)

    # ------------------------------------------------------
    device_id = (data.get("device_id") or "").strip()
    if not device_id:
        EVENTS.append(data)
        return ("", 204)

    now = datetime.now(timezone.utc)
    LAST_SEEN_IP[ip].append(now)
    if device_id:
        LAST_SEEN_DEVICE[device_id].append(now)

    dwell = data.get("dwell_ms") or 0
    evt_type = (data.get("type") or "").lower()

    # Dwell previo para patrón repetido
    last_dwell_dev = LAST_DWELL_DEVICE.get(device_id) if device_id else None
    last_dwell_ip = LAST_DWELL_IP.get(ip)

    # GEO + risk
    geo = geo_lookup(ip)

    data["ip"] = ip
    data["device_id"] = device_id
    data["ts"] = now_iso()
    data["geo"] = geo
    data["last_dwell_device"] = last_dwell_dev
    data["last_dwell_ip"] = last_dwell_ip
    data["risk"] = compute_risk(data)

    # Actualizar dwell
    if device_id and dwell:
        LAST_DWELL_DEVICE[device_id] = dwell
    if dwell:
        LAST_DWELL_IP[ip] = dwell

    # ------------------------------------------------------
    # 🔥 Bloqueo por rango seguro (/24)
    # ------------------------------------------------------
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            range_24 = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            data["range_24"] = range_24
    except:
        data["range_24"] = "-"

    # Si IP pertenece a rango ya bloqueado → fuera
    if is_ip_in_blocked_range(ip):
        data["autoblocked"] = {"by": "range", "reason": "blocked_range"}
        EVENTS.append(data)
        return ("", 403)
    # 🔥 Bloqueo por ASN + ISP tipo VPN/Datacenter
    asn = geo.get("asn")
    isp = (geo.get("isp") or "").lower()

    if asn and any(dc in isp for dc in KNOWN_DATACENTERS):
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                range_24 = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                BLOCK_RANGES.add(range_24)
        except:
            pass

        BLOCK_IPS.add(ip)
        data["autoblocked"] = {"by": "asn", "reason": "datacenter"}
        save_storage()
        EVENTS.append(data)
        return ("", 403)

    # ------------------------------------------------------
    # 🧠 Lógica de riesgo + repetición
    # ------------------------------------------------------
    repeats = touches_in_window_device(device_id, SETTINGS["repeat_window_seconds"]) \
        if device_id else touches_in_window_ip(ip, SETTINGS["repeat_window_seconds"])

    # Whitelist = permitir siempre
    if device_id in WHITELIST_DEVICES or ip in WHITELIST_IPS:
        data["blocked"] = False
        EVENTS.append(data)
        return ("", 204)

    autoblock = False
    reason_ab = None

    # No bloquear solo por land, necesitamos patrón
    if evt_type != "land" and SETTINGS["risk_autoblock"] and data["risk"]["suspicious"]:
        autoblock = True
        reason_ab = "risk"

    # Si NO hay repetición, no bloquear
    if repeats < SETTINGS["repeat_required"]:
        autoblock = False

    # 2️⃣ WhatsApp pero repetido sospechoso
    if evt_type == "whatsapp_click" and repeats >= SETTINGS["repeat_required"]:
        if not had_good_dwell_recently(device_id, SETTINGS["good_dwell_window_minutes"], SETTINGS["min_good_dwell_ms"]):
            autoblock = True
            reason_ab = "wa_repeats"

    # 3️⃣ Fast-click pattern (NO penaliza WhatsApp)
    if evt_type != "whatsapp_click" and dwell < SETTINGS["fast_dwell_ms"] and repeats >= SETTINGS["fast_repeat_required"]:
        autoblock = True
        reason_ab = "fast_repeats"

    # 4️⃣ ISP sospechoso
    if any(dc in isp for dc in KNOWN_DATACENTERS):
        autoblock = True
        reason_ab = "isp_datacenter"
    # ------------------------------------------------------
    # 🔥 Bloqueo final
    # ------------------------------------------------------
    if autoblock:
        if device_id:
            BLOCK_DEVICES.add(device_id)
            data["autoblocked"] = {"by": "device", "reason": reason_ab}
        else:
            BLOCK_IPS.add(ip)
            data["autoblocked"] = {"by": "ip", "reason": reason_ab}

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

@app.get("/api/stats/geo")
def geo_stats():
    counter = defaultdict(int)
    for ev in EVENTS:
        c = (ev.get("geo") or {}).get("country") or "?"
        counter[c] += 1
    return jsonify(counter)

@app.get("/api/stats/asn")
def asn_stats():
    counter = defaultdict(int)
    for ev in EVENTS:
        a = (ev.get("geo") or {}).get("asn") or "?"
        counter[a] += 1
    return jsonify(counter)

@app.get("/api/amiblocked")
def api_am_i_blocked():
    device_id = request.args.get("device_id", "").strip()
    ip = get_client_ip()

    blocked_device = device_id in BLOCK_DEVICES if device_id else False
    blocked_ip     = ip in BLOCK_IPS

    return jsonify({
        "blocked": blocked_device or blocked_ip,
        "blocked_by": "device" if blocked_device else ("ip" if blocked_ip else None)
    })

@app.get("/api/stats/devices")
def device_stats():
    return jsonify({
        "total_devices": len(LAST_SEEN_DEVICE),
        "blocked_devices": len(BLOCK_DEVICES),
        "whitelisted_devices": len(WHITELIST_DEVICES)
    })


# Cargar memoria persistente
load_storage()

# ✅ Run
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
