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
    if (dwell < 800) return "Se fue en < 1s (posible bot)";
    if (dwell < 3000) return "Visitó y salió rápido";
    return "Estuvo navegando normalmente";
  }
  return "Actividad detectada";
}

function origen(r) {
  const ref = (r.ref || "").toLowerCase();
  const url = (r.url || "").toLowerCase();
  const gclid = r.gclid || null;
  if (gclid) return "Google Ads (gclid)";
  if (ref.includes("google")) return "Búsqueda orgánica Google";
  if (ref.includes("facebook")) return "Facebook";
  if (ref.includes("instagram")) return "Instagram";
  if (ref.includes("wa.me")) return "WhatsApp";
  if (!ref) return "Tráfico directo";
  return "Otro sitio";
}

// ==========================
// Bloqueo / Desbloqueo (DEVICE & IP)
// ==========================
async function blockDevice(device_id) {
  try {
    if (!device_id) { alert("Sin device_id"); return; }
    const res = await fetch("/api/blockdevices", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id })
    });
    if (!res.ok) throw new Error();
    loadData();
  } catch (e) {
    alert("Error al bloquear el dispositivo");
  }
}

async function unblockDevice(device_id) {
  try {
    if (!device_id) { alert("Sin device_id"); return; }
    const res = await fetch("/api/blockdevices", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id })
    });
    if (!res.ok) throw new Error();
    loadData();
  } catch (e) {
    alert("Error al desbloquear el dispositivo");
  }
}

async function blockIp(ip) {
  try {
    if (!ip) { alert("Sin IP"); return; }
    const res = await fetch("/api/blockips", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });
    if (!res.ok) throw new Error();
    loadData();
  } catch (e) {
    alert("Error al bloquear la IP");
  }
}

async function unblockIp(ip) {
  try {
    if (!ip) { alert("Sin IP"); return; }
    const res = await fetch("/api/blockips", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });
    if (!res.ok) throw new Error();
    loadData();
  } catch (e) {
    alert("Error al desbloquear la IP");
  }
}

// ==========================
// Render fila
// ==========================
function renderRow(r) {
  const dwell = r.dwell_ms ?? 0;
  const isWA = r.type === "whatsapp_click";

  // 🔴 estado EN VIVO (calculado por el backend)
  const blockedNow = !!r.blocked_now;
  const blockedBy  = r.blocked_by || (r.device_id && r.blocked ? "device" : (r.blocked ? "ip" : null));

  // ¿Qué acción usar?
  const hasDevice = !!r.device_id;
  const blockCall   = hasDevice ? `blockDevice('${r.device_id}')`   : `blockIp('${r.ip}')`;
  const unblockCall = hasDevice ? `unblockDevice('${r.device_id}')` : `unblockIp('${r.ip}')`;

  return `
    <tr class="${isWA ? 'row-whatsapp' : ''} ${blockedNow ? 'row-blocked' : ''}">
      <td>${r.ts}</td>
      <td class="mono">${r.ip || '-'}</td>
      <td class="mono" style="max-width:220px;white-space:normal;">${r.device_id || "<span style='opacity:.4'>-</span>"}</td>
      <td>${r.geo?.city || "-"}, ${r.geo?.region || ""}<br><small>${r.geo?.isp || ""}</small></td>
      <td>${translateEvent(r.type)}</td>
      <td>${r.ref || "-"}</td>
      <td>${origen(r)}</td>
      <td>${dwell ? dwell + " ms" : "-"}</td>
      <td><span class="badge ${riskToLevel(r.risk?.score || 0)}">${riskToLevel(r.risk?.score || 0)}</span></td>
      <td>
        ${blockedNow
          ? `<strong style="color:#ef4444">Bloqueado (${blockedBy})</strong>`
          : `<span style="color:#10b981">Activo</span>`}
      </td>
      <td>
        <button class="map-btn" onclick="openMap('${r.geo?.lat}','${r.geo?.lon}','${r.geo?.city}')">Ver mapa</button>
        ${blockedNow
          ? `<button style="margin-left:6px" onclick="${unblockCall}" class="map-btn">Desbloquear</button>`
          : `<button style="margin-left:6px;background:#ef4444;color:white" onclick="${blockCall}" class="map-btn">Bloquear</button>`}
      </td>
    </tr>
  `;
}

// ==========================
// Cargar datos
// ==========================
async function loadData() {
  const onlySuspicious = document.getElementById("onlySuspicious").checked;
  const search = (document.getElementById("search").value || "").toLowerCase();

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
      (x.device_id || "").toLowerCase().includes(search) ||
      (x.geo?.city || "").toLowerCase().includes(search) ||
      (x.geo?.region || "").toLowerCase().includes(search) ||
      (x.geo?.isp || "").toLowerCase().includes(search) ||
      (x.type || "").toLowerCase().includes(search) ||
      origen(x).toLowerCase().includes(search)
    );
  }

  document.getElementById("tbody").innerHTML = data.map(renderRow).join("");
  document.getElementById("kpiSummary").innerText = `Total: ${data.length}`;
}

// ==========================
// Map modal
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
