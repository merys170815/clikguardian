// ==========================
// Helpers (riesgo, eventos, origen)
// ==========================
function riskToLevel(score) {
  if (score >= 80) return "alto";
  if (score >= 40) return "medio";
  return "bajo";
}

function translateEvent(event) {
  if (event === "land") return "Entrada a la página";
  if (event === "leave") return "Salida de la página";
  if (event === "whatsapp_click") return "Clic en WhatsApp ✅";
  return "Actividad";
}

function explain(event, dwell) {
  if (event === "land") return "Entró a la página";
  if (event === "whatsapp_click") return "Hizo clic real en el botón de WhatsApp";
  if (event === "leave") {
    if (!dwell) return "Salió rápidamente";
    if (dwell < 800) return "Se fue en menos de 1 segundo (posible bot o clic inválido)";
    if (dwell < 3000) return "Visitó la página pero salió rápido";
    return "Estuvo navegando normalmente";
  }
  return "Actividad detectada";
}

function origen(r) {
  const ref = (r.ref || "").toLowerCase();
  const url = (r.url || "").toLowerCase();
  const gclid = r.gclid || null;
  if (gclid) return "Google Ads (gclid detectado)";
  if (ref.includes("google")) return "Búsqueda orgánica Google";
  if (ref.includes("facebook")) return "Facebook";
  if (ref.includes("instagram")) return "Instagram";
  if (ref.includes("wa.me")) return "WhatsApp";
  if (!ref) return "Tráfico directo";
  return "Otro sitio";
}

// ==========================
// Bloqueo / Desbloqueo desde panel
// ==========================
async function blockIp(ip){
  try{
    await fetch("/api/blocklist", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ ip })
    });
    loadData();
  }catch(e){ console.error(e); alert("Error al bloquear"); }
}

async function unblockIp(ip){
  try{
    await fetch("/api/blocklist", {
      method: "DELETE",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ ip })
    });
    loadData();
  }catch(e){ console.error(e); alert("Error al desbloquear"); }
}

// ==========================
// Render fila
// ==========================
function renderRow(r) {
  const dwell = r.dwell_ms ?? 0;
  const isWA = r.type === "whatsapp_click";
  const rowClass = isWA ? "row-whatsapp" : "";
  const blocked = r.blocked ? true : false;

  return `
    <tr class="${rowClass} ${blocked ? 'row-blocked' : ''}">
      <td>${r.ts}</td>
      <td class="mono">${r.ip}</td>
      <td>${r.geo?.city || "-"}, ${r.geo?.region || ""}<br><small>${r.geo?.isp || ""}</small></td>
      <td>${translateEvent(r.type)}</td>
      <td>${r.ref || "-"}</td>
      <td>${origen(r)}</td>
      <td>${dwell ? dwell + " ms" : "-"}</td>
      <td><span class="badge ${riskToLevel(r.risk?.score || 0)}">${riskToLevel(r.risk?.score || 0)}</span></td>
      <td>${explain(r.type, dwell)}</td>
      <td>
        <button class="map-btn" onclick="openMap('${r.geo?.lat}','${r.geo?.lon}','${r.geo?.city}')">Ver mapa</button>
        ${ blocked
          ? `<button style="margin-left:6px" onclick="unblockIp('${r.ip}')" class="map-btn">Desbloquear</button>`
          : `<button style="margin-left:6px;background:#ef4444;color:white" onclick="blockIp('${r.ip}')" class="map-btn">Bloquear</button>`}
      </td>
    </tr>
  `;
}

// ==========================
// Cargar datos
// ==========================
async function loadData() {
  const onlySuspicious = document.getElementById("onlySuspicious").checked;
  const search = document.getElementById("search").value.toLowerCase();

  let data = [];

  try {
    const res = await fetch("/api/events");
    const json = await res.json();
    data = json.events || [];
  } catch (e) {
    console.error("Error cargando eventos", e);
  }

  if (onlySuspicious) {
    data = data.filter(ev => (ev.risk?.score || 0) >= 40);
  }

  if (search) {
    data = data.filter(x =>
      (x.ip || "").toLowerCase().includes(search) ||
      (x.geo?.city || "").toLowerCase().includes(search) ||
      (x.geo?.region || "").toLowerCase().includes(search) ||
      (x.geo?.isp || "").toLowerCase().includes(search) ||
      (x.type || "").toLowerCase().includes(search) ||
      origen(x).toLowerCase().includes(search)
    );
  }

  document.getElementById("tbody").innerHTML =
    data.map(renderRow).join("");

  document.getElementById("kpiSummary").innerText = `Total: ${data.length}`;
}

// ==========================
// Map modal (igual que antes)
// ==========================
let map = null;

function openMap(lat, lon, city) {
  const modal = document.getElementById("mapModal");
  modal.style.display = "flex";
  if (!map) {
    map = L.map('map').setView([lat, lon], 12);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {}).addTo(map);
  } else {
    map.setView([lat, lon], 12);
  }
  L.marker([lat, lon]).addTo(map);
  document.getElementById("mapTitle").innerText = "Ubicación aproximada: " + city;
}

document.getElementById("closeMap").onclick = () => document.getElementById("mapModal").style.display = "none";
document.getElementById("zoomIn").onclick = () => map && map.zoomIn();
document.getElementById("zoomOut").onclick = () => map && map.zoomOut();

// ==========================
// Auto-reload
// ==========================
loadData();
document.getElementById("refresh").onclick = loadData;
setInterval(loadData, 5000);
