// ==========================
// ✅ DETECTAR NIVEL DE RIESGO
// ==========================
function riskToLevel(score) {
  if (score >= 80) return "alto";
  if (score >= 40) return "medio";
  return "bajo";
}

// ==========================
// ✅ TRADUCIR EVENTOS A ESPAÑOL
// ==========================
function translateEvent(event) {
  if (event === "land") return "Entrada a la página";
  if (event === "leave") return "Salida de la página";
  if (event === "whatsapp_click") return "Clic en WhatsApp ✅";
  return "Actividad";
}

// ==========================
// ✅ EXPLICACIÓN EN LENGUAJE HUMANO
// ==========================
function explain(event, dwell) {
  if (event === "land")
    return "Entró a la página";

  if (event === "whatsapp_click")
    return "Hizo clic real en el botón de WhatsApp";

  if (event === "leave") {
    if (!dwell) return "Salió rápidamente";

    if (dwell < 800)
      return "Se fue en menos de 1 segundo (posible bot o clic inválido)";

    if (dwell < 3000)
      return "Visitó la página pero salió rápido";

    return "Estuvo navegando normalmente";
  }

  return "Actividad detectada";
}

// ==========================
// ✅ ORIGEN DEL TRÁFICO
// ==========================
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
// ✅ RENDER DE FILAS
// ==========================
function renderRow(r) {
  const dwell = r.dwell_ms ?? 0;

  const isWA = r.type === "whatsapp_click";
  const rowClass = isWA ? "row-whatsapp" : "";

  return `
    <tr class="${rowClass}">
      <td>${r.ts}</td>
      <td class="mono">${r.ip}</td>

      <td>
        ${r.geo?.city || "-"}, ${r.geo?.region || ""}
        <br><small>${r.geo?.isp || ""}</small>
      </td>

      <td>${translateEvent(r.type)}</td>

      <td>${r.ref || "-"}</td>

      <td>${origen(r)}</td>   <!-- ✅ AQUI ESTÁ LA NUEVA COLUMNA -->

      <td>${dwell ? dwell + " ms" : "-"}</td>

      <td>
        <span class="badge ${riskToLevel(r.risk?.score || 0)}">
          ${riskToLevel(r.risk?.score || 0)}
        </span>
      </td>

      <td>${explain(r.type, dwell)}</td>

      <td>
        <button class="map-btn"
          onclick="openMap('${r.geo?.lat}','${r.geo?.lon}','${r.geo?.city}')">
          Ver mapa
        </button>
      </td>
    </tr>
  `;
}

// ==========================
// ✅ CARGAR DATOS DEL SERVIDOR
// ==========================
async function loadData() {
  const onlySuspicious = document.getElementById("onlySuspicious").checked;
  const search = document.getElementById("search").value.toLowerCase();

  let data = [];

  try {
    const res = await fetch("https://clikguardian.onrender.com/api/events");
    const json = await res.json();
    data = json.events || [];
  } catch (e) {
    console.error("Error cargando eventos", e);
  }

  // Filtrar sospechosos
  if (onlySuspicious) {
    data = data.filter(ev => riskToLevel(ev.risk?.score || 0) !== "bajo");
  }

  // Filtro búsqueda
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

  // Pintar tabla
  document.getElementById("tbody").innerHTML =
    data.map(renderRow).join("");

  // KPI
  document.getElementById("kpiSummary").innerText =
    `Total: ${data.length}`;
}

// ==========================
// ✅ MAPA
// ==========================
let map = null;

function openMap(lat, lon, city) {
  const modal = document.getElementById("mapModal");
  modal.style.display = "flex";

  if (!map) {
    map = L.map('map').setView([lat, lon], 12);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {})
      .addTo(map);
  } else {
    map.setView([lat, lon], 12);
  }

  L.marker([lat, lon]).addTo(map);

  document.getElementById("mapTitle").innerText =
    "Ubicación aproximada: " + city;
}

document.getElementById("closeMap").onclick =
  () => document.getElementById("mapModal").style.display = "none";

document.getElementById("zoomIn").onclick = () => map.zoomIn();
document.getElementById("zoomOut").onclick = () => map.zoomOut();

// ==========================
// ✅ AUTO RECARGA
// ==========================
loadData();
document.getElementById("refresh").onclick = loadData;
setInterval(loadData, 5000);
