from flask import Flask, request, jsonify, render_template
from datetime import datetime, timezone
from collections import deque
import requests

app = Flask(__name__)

# Base temporal en memoria (luego puedes poner DB si quieres)
EVENTS = deque(maxlen=5000)
BLOCK = set()

# -------------------------------
# ✅ FUNCIÓN PREMIUM: GEOLOCALIZACIÓN
# -------------------------------
def geo_from_ip(ip: str):
    """
    Usa ipapi.co para obtener ciudad, región, distrito/localidad, país y proveedor.
    Esto te dará zonas como: Chapinero, Suba, Bosa, Kennedy (si el proveedor tiene ese dato)
    """
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        if r.status_code == 200:
            j = r.json()
            return {
                "city": j.get("city"),
                "region": j.get("region"),
                "locality": j.get("district"),   # A veces viene el barrio/localidad
                "country": j.get("country_name"),
                "org": j.get("org"),             # Operador: Claro, Tigo, Movistar, ETB
                "postal": j.get("postal"),
                "latitude": j.get("latitude"),
                "longitude": j.get("longitude")
            }
    except:
        pass
    return {}


# -------------------------------
# ✅ PÁGINA PRINCIPAL (DASHBOARD)
# -------------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -------------------------------
# ✅ TRACKING (RECIBE CLICKS DE TU PÁGINA)
# -------------------------------
@app.post("/track")
def track():
    data = request.get_json(force=True, silent=True) or {}

    # Obtener IP real
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if "," in ip:
        ip = ip.split(",")[0].strip()  # por si es lista de proxies

    data["ip"] = ip
    data["ts"] = datetime.now(timezone.utc).isoformat()

    # ✅ GEOLOCALIZACIÓN PREMIUM
    data["geo"] = geo_from_ip(ip)

    # ✅ Detección de dwell
    dwell = data.get("dwell_ms", 0)

    # -------------------------------
    # ✅ AI RULES: DETECTAR CLICK FALSO / BOT / FRAUDULENTO
    # -------------------------------
    suspicion_score = 0

    # Regla 1: dwell muy bajo
    if dwell > 0 and dwell < 800:
        suspicion_score += 35

    # Regla 2: repetición desde la misma IP
    rep_count = sum(1 for e in EVENTS if e.get("ip") == ip)
    if rep_count > 3:
        suspicion_score += 40

    # Regla 3: proveedor sospechoso (Bots usan ASNs genéricos)
    org = data["geo"].get("org", "").lower()
    if "amazon" in org or "google" in org or "digitalocean" in org or "ovh" in org:
        suspicion_score += 50  # hosting => casi siempre bot

    # Regla 4: User-Agent vacío o raro
    ua = data.get("ua", "").lower()
    if ua == "" or "headless" in ua or "python" in ua or "bot" in ua:
        suspicion_score += 70

    # ✅ Marcamos en el evento
    data["fraud_score"] = suspicion_score

    # Marcar como sospechoso si supera un umbral
    data["suspect"] = suspicion_score >= 40

    # ✅ Bloque automático si supera 80 (puedes cambiarlo)
    if suspicion_score >= 80:
        BLOCK.add(ip)
        data["blocked_auto"] = True
    else:
        data["blocked_auto"] = False

    # Marcar si ya estaba bloqueada
    data["blocked"] = ip in BLOCK

    # Guardar evento
    EVENTS.append(data)
    return ("", 204)


# -------------------------------
# ✅ LISTAR EVENTOS PARA TU DASHBOARD
# -------------------------------
@app.get("/api/events")
def api_events():
    limit = int(request.args.get("limit", 200))
    evs = list(EVENTS)[-limit:]
    evs.reverse()
    return jsonify({"events": evs})


# -------------------------------
# ✅ API BLOCKLIST
# -------------------------------
@app.get("/api/blocklist")
def get_blocklist():
    return jsonify(sorted(list(BLOCK)))

@app.post("/api/blocklist")
def add_block():
    data = request.get_json(force=True) or {}
    ip = data.get("ip")
    if ip:
        BLOCK.add(ip)
    return jsonify({"ok": True, "size": len(BLOCK)})

@app.delete("/api/blocklist")
def del_block():
    data = request.get_json(force=True) or {}
    ip = data.get("ip")
    if ip and ip in BLOCK:
        BLOCK.remove(ip)
    return jsonify({"ok": True, "size": len(BLOCK)})


# -------------------------------
# ✅ EJECUCIÓN LOCAL
# -------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
