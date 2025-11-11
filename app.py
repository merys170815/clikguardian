from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from functools import lru_cache
import requests, re, logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = Flask(__name__)

# CORS CORREGIDO
CORS(app, resources={
    r"/track": {"origins": [
        "https://medigoencasa.com",
        "https://www.medigoencasa.com",
        "https://clikguardian.onrender.com",
        "http://localhost",
        "http://127.0.0.1"
    ]},
    r"/api/*": {"origins": "*"},
    r"/guard": {"origins": "*"}
})

# =========================
# ESTADOS EN MEMORIA
# =========================
EVENTS = deque(maxlen=20000)

BLOCK_DEVICES = set()
BLOCK_IPS = set()

LAST_SEEN_DEVICE = defaultdict(deque)
LAST_SEEN_IP = defaultdict(deque)

SETTINGS = {
    "risk_autoblock": True,
    "risk_threshold": 80,
    "repeat_window_seconds": 60,
    "repeat_window_min": 60,
    "repeat_required": 2,
    "fast_dwell_ms": 600,
    "fast_repeat_required": 3,
}

BOT_UA_PAT = re.compile(
    r"bot|crawler|spider|preview|scan|archiver|pingdom|curl|wget|ahrefs",
    re.I
)

# =========================
# HELPERS
# =========================
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
def geo_lookup(ip):
    if not ip or ip.startswith(("127.","10.","192.168.","::1")):
        return {"country":"LOCAL","region":"-","city":"-","isp":"LAN","lat":0,"lon":0,"vpn":False}
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=4)
        j = r.json()
        conn = j.get("connection",{}) or {}
        sec = j.get("security",{}) or {}
        return {
            "country": j.get("country","-"),
            "region": j.get("region","-"),
            "city": j.get("city","-"),
            "isp": conn.get("isp") or j.get("org","-"),
            "lat": j.get("latitude",0),
            "lon": j.get("longitude",0),
            "vpn": bool(sec.get("vpn",False))
        }
    except:
        return {"country":"-","region":"-","city":"-","isp":"-","lat":0,"lon":0,"vpn":False}

def _prune_window(dq, cutoff):
    while dq and dq[0] < cutoff:
        dq.popleft()

def count_recent(dq, seconds):
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    _prune_window(dq, cutoff)
    return len(dq)

def compute_risk(ev):
    score = 0
    reasons = []

    dwell = ev.get("dwell_ms") or 0
    if dwell and dwell < 800:
        score += 30

    ua = (ev.get("ua") or "").lower()
    if BOT_UA_PAT.search(ua):
        score += 25

    ref = ev.get("ref","")
    url = ev.get("url","")
    if ("google" in ref or "gclid" in url) and "gclid" not in url:
        score += 25

    geo = ev.get("geo") or {}
    if geo.get("country") and geo["country"] not in ("LOCAL","Colombia","CO"):
        score += 10
    if geo.get("vpn"):
        score += 15

    if ev.get("type") == "whatsapp_click":
        score = max(0, score - 30)

    score = min(100, score)
    return {"score":score}

# =========================
# UI
# =========================
@app.route("/")
def home():
    return render_template("index.html")

# =========================
# GUARD
# =========================
@app.post("/guard")
def guard():
    data = request.get_json(force=True, silent=True) or {}
    device_id = data.get("device_id") or ""
    ip = get_client_ip()

    if device_id and device_id in BLOCK_DEVICES:
        return jsonify({"blocked":True,"by":"device"}), 403

    if ip in BLOCK_IPS:
        return jsonify({"blocked":True,"by":"ip"}), 403

    return jsonify({"blocked":False})

# =========================
# TRACKER
# =========================
@app.route("/track", methods=["POST","OPTIONS"])
def track():
    if request.method == "OPTIONS":
        return ("",204)

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

    EVENTS.append(data)
    return ("",204)

# =========================
# EVENTS CON BLOQUEO EN VIVO
# =========================
@app.get("/api/events")
def api_events():
    evs = list(EVENTS)[-200:]
    evs.reverse()

    out = []
    for ev in evs:
        device_id = ev.get("device_id")
        ip = ev.get("ip")

        blocked_device = device_id in BLOCK_DEVICES if device_id else False
        blocked_ip = ip in BLOCK_IPS

        blocked_now = blocked_device or blocked_ip

        if blocked_device:
            blocked_by = "device"
        elif blocked_ip:
            blocked_by = "ip"
        else:
            blocked_by = None

        out.append({
            **ev,
            "blocked_now": blocked_now,
            "blocked_by": blocked_by
        })

    return jsonify({"events": out})

# =========================
# BLOQUEO MANUAL DEVICE
# =========================
@app.post("/api/blockdevices")
def block_device():
    data = request.get_json(force=True) or {}
    device_id = (data.get("device_id") or "").strip()
    if not device_id:
        return jsonify({"ok":False,"error":"device_id requerido"}),400

    BLOCK_DEVICES.add(device_id)
    return jsonify({"ok":True,"blocked":device_id})

@app.delete("/api/blockdevices")
def unblock_device():
    data = request.get_json(force=True) or {}
    device_id = (data.get("device_id") or "").strip()
    if device_id in BLOCK_DEVICES:
        BLOCK_DEVICES.remove(device_id)
        return jsonify({"ok":True,"unblocked":device_id})
    return jsonify({"ok":False,"error":"device_id no encontrado"}),404

# =========================
# BLOQUEO MANUAL IP
# =========================
@app.post("/api/blockips")
def block_ip():
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok":False,"error":"ip requerida"}),400

    BLOCK_IPS.add(ip)
    return jsonify({"ok":True,"blocked":ip})

@app.delete("/api/blockips")
def unblock_ip():
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if ip in BLOCK_IPS:
        BLOCK_IPS.remove(ip)
        return jsonify({"ok":True,"unblocked":ip})
    return jsonify({"ok":False,"error":"ip no encontrada"}),404

# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
