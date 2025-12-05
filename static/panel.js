// ==========================
// Evento de entrada (LAND)
// ==========================
(async () => {
  await initDevice();
  sendEvent({
    type: "land",
    ts: Date.now(),
    url: location.href,
    ref: document.referrer,
    ua: navigator.userAgent,
    lang: navigator.language,
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    platform: navigator.platform,
    screen: `${window.screen.width}x${window.screen.height}`
  });
})();


// ==========================
// Evento de salida (LEAVE)
// ==========================
window.addEventListener("beforeunload", () => {
  sendEvent({
    type: "leave",
    ts: Date.now()
  });
});

// ==========================
// IDENTIFICADOR REAL ÚNICO
// ==========================

let DEVICE_ID = null;

// *** SALT secreto — cámbialo para ti ***
const CG_SALT = "MEDIGOENCASA-2025";

async function initDevice() {
  // 1️⃣ Si ya existe, úsalo
  const stored = localStorage.getItem("cg_device_id_v2");
  if (stored) {
    DEVICE_ID = stored;
    return;
  }

  // 2️⃣ Obtener fingerprint base
  let finger = await getFingerprintBase();

  // 3️⃣ timestamp de instalación
  let installTs = localStorage.getItem("cg_install_ts_v2");
  if (!installTs) {
    installTs = Date.now().toString();
    localStorage.setItem("cg_install_ts_v2", installTs);
  }

  // 4️⃣ mezcla final
  const raw = finger + "|" + installTs + "|" + CG_SALT;

  // 5️⃣ hash
  const finalID = "perm-" + btoa(raw).substring(0,38);

  // 6️⃣ guardar
  localStorage.setItem("cg_device_id_v2", finalID);
  DEVICE_ID = finalID;
}

// *** Fingerprint base — NO único pero estable ***
async function getFingerprintBase(){
  // persistent para que no cambie
  let pid = localStorage.getItem("cg_persistent_id_v2");
  if (!pid) {
    pid = crypto.randomUUID();
    localStorage.setItem("cg_persistent_id_v2", pid);
  }

  // canvas
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  ctx.textBaseline = "top";
  ctx.font = "16px Arial";
  ctx.fillStyle = "#f60";
  ctx.fillText("MGC-FP", 2, 2);
  const canvasFP = canvas.toDataURL();

  // básico
  const basicRaw = [
    navigator.userAgent,
    navigator.language,
    Intl.DateTimeFormat().resolvedOptions().timeZone,
    navigator.platform,
    `${screen.width}x${screen.height}`
  ].join("|");

  return pid + "|" + canvasFP.substring(0,40) + "|" + basicRaw;
}

// ==========================
// SEND EVENT
// ==========================
async function sendEvent(data) {
  // asegurar ID
  if (!DEVICE_ID) {
    const stored = localStorage.getItem("cg_device_id_v2");
    if (stored) {
      DEVICE_ID = stored;
    } else {
      await initDevice();
    }
  }

  data.device_id = DEVICE_ID;

  fetch("/track", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
    keepalive:true
  });
}
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

function renderClientMeta(r) {
  return `
    <div class="meta-box">
      <strong>UA:</strong> ${r.ua || "-"}<br>
      <strong>Lang:</strong> ${r.lang || "-"}<br>
      <strong>TZ:</strong> ${r.tz || "-"}<br>
      <strong>Platform:</strong> ${r.platform || "-"}<br>
      <strong>Screen:</strong> ${r.screen || "-"}<br>
      <strong>Keyword:</strong> ${r.keyword || "-"}
    </div>
  `;
}

// ==========================
// Ocultar filas solo en el panel (no borra de storage)
// ==========================
const HIDDEN_KEY = "cg_hidden_events";

// lee del localStorage
function getHiddenSet() {
  try {
    const raw = localStorage.getItem(HIDDEN_KEY);
    if (!raw) return new Set();
    return new Set(JSON.parse(raw));
  } catch (e) {
    return new Set();
  }
}

function saveHiddenSet(set) {
  try {
    localStorage.setItem(HIDDEN_KEY, JSON.stringify([...set]));
  } catch (e) {}
}

// Genera una clave única del evento
function eventKey(r) {
  return (r.ts || "") + "|" + (r.ip || "") + "|" + (r.device_id || "");
}

// Oculta una fila (solo visual)
function hideRow(ts, ip, device_id) {
  const set = getHiddenSet();
  const key = (ts || "") + "|" + (ip || "") + "|" + (device_id || "");
  set.add(key);
  saveHiddenSet(set);
  // volver a pintar la tabla
  loadData();
}

// ==========================
// Render fila (CON CAMPO SITIO Y X ROJA)
// ==========================
function renderRow(r) {
  const dwell = r.dwell_ms ?? 0;
  const isWA = r.type === "whatsapp_click";

  const blockedNow = !!r.blocked_now;

  let blockedLabel = "-";
  if (blockedNow) {
    if (r.blocked_by === "device") blockedLabel = "Bloqueado (device)";
    else if (r.blocked_by === "ip") blockedLabel = "Bloqueado (IP)";
    else blockedLabel = "Bloqueado";
  }

  const hasDevice = !!(r.device_id && r.device_id !== "");

  const blockCall = hasDevice
    ? `blockDevice('${r.device_id}')`
    : `blockIp('${r.ip}')`;

  const unblockCall = hasDevice
    ? `unblockDevice('${r.device_id}')`
    : `unblockIp('${r.ip}')`;

  return `
    <tr class="${isWA ? 'row-whatsapp' : ''} ${blockedNow ? 'row-blocked' : ''}">
      <td>${r.ts || "-"}</td>
      <td>${r.ip || "-"}</td>

      <td>${hasDevice ? r.device_id : "<span style='opacity:.4'>Sin Device ID</span>"}</td>

      <td>
        ${r.geo?.city || "-"}, ${r.geo?.region || ""}
        <br><small>${r.geo?.isp || ""}</small>
      </td>

      <td>${r.site || "-"}</td>

      <td>${translateEvent(r.type)}</td>

      <td>
        ${translateEvent(r.type)}
        <br>
        <button class="meta-btn" onclick="showMeta(${JSON.stringify(r).replace(/"/g, '&quot;')})">
        Ver meta
        </button>
      </td>

      <td>${r.ref || "-"}</td>
      <td>${origen(r)}</td>
      <td>${dwell ? dwell + " ms" : "-"}</td>

      <td>
        <span class="badge ${riskToLevel(r.risk?.score || 0)}">
          ${riskToLevel(r.risk?.score || 0)}
        </span>
      </td>

      <td>
        ${blockedNow
          ? `<strong style="color:#ef4444">${blockedLabel}</strong>`
          : `<span style="color:#10b981">Activo</span>`
        }
      </td>

     <td>
        <button class="map-btn" onclick="openMap('${r.geo?.lat}','${r.geo?.lon}','${r.geo?.city}')">
          Ver mapa
        </button>

       ${
          blockedNow
            ? `<button style="margin-left:6px" onclick="${unblockCall}">
                 Desbloquear
               </button>`
            : `<button style="margin-left:6px;background:#ef4444;color:white"
                 onclick="${blockCall}">
                 Bloquear
               </button>`
        }
      </td>

      <!-- ⚡ BOTÓN ROJO X PARA BORRAR SOLO DEL PANEL (sin afectar memoria) -->
      <td>
        <button onclick="hideRow('${r.ts || ""}','${r.ip || ""}','${r.device_id || ""}')"
                style="color:white;background:#dc2626;border:none;padding:6px 10px;border-radius:6px;cursor:pointer;">
          ❌
        </button>
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

  // Filtrar sospechosos
  if (onlySuspicious) {
    data = data.filter(ev => (ev.risk?.score || 0) >= 40);
  }

  // Filtrar filas ocultas solo en el panel
  const hidden = getHiddenSet();
  data = data.filter(ev => !hidden.has(eventKey(ev)));

  // Buscador
  if (search) {
    const s = search;
    data = data.filter(x =>
      (x.ip || "").toLowerCase().includes(s) ||
      (x.device_id || "").toLowerCase().includes(s) ||
      (x.geo?.city || "").toLowerCase().includes(s) ||
      (x.geo?.region || "").toLowerCase().includes(s) ||
      (x.geo?.isp || "").toLowerCase().includes(s) ||
      (x.type || "").toLowerCase().includes(s) ||
      origen(x).toLowerCase().includes(s)
    );
  }

  // Pintar tabla
  document.getElementById("tbody").innerHTML = data.map(renderRow).join("");
  document.getElementById("kpiSummary").innerText = `Total: ${data.length}`;
}

function removeRow(index) {
  const row = document.getElementById("row_" + index);
  if (row) row.remove();
}
function showMeta(r) {
  const box = document.getElementById("metaBox");
  box.innerHTML = renderClientMeta(r);
  box.style.display = "block";
}

document.addEventListener("click", (e) => {
  if (e.target.id !== "metaBox") {
    document.getElementById("metaBox").style.display = "none";
  }
});


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
