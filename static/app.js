// ==========================
// ✅ FUNCIONES DE APOYO
// ==========================

// Convertir score en nivel "bajo / medio / alto"
function riskToLevel(score) {
  if (score >= 80) return "alto";
  if (score >= 40) return "medio";
  return "bajo";
}

// Traducción explicada para humanos
function explain(type, dwell) {

  if (type === "land")
    return "Entró a la página";

  if (type === "whatsapp_click")
    return "Hizo clic real en el botón de WhatsApp";

  if (type === "leave") {
    if (!dwell) return "Salió muy rápido";

    if (dwell < 800)
      return "Se fue en menos de 1 segundo (posible clic inválido o bot)";

    if (dwell < 3000)
      return "Visitó la página pero salió rápido";

    return "Navegó de forma normal por la página";
  }

  return "Actividad detectada";
}

// Palabra del evento traducida
function translateEvent(type){
  if(type === "land") return "Entrada";
  if(type === "leave") return "Salida";
  if(type === "whatsapp_click") return "WhatsApp";
  return type;
}


// ==========================
// ✅ RENDER FILA
// ==========================
function renderRow(ev){

  const dwell = ev.dwell_ms ?? 0;
  const riskScore = ev.risk?.score ?? 0;
  const riskLevel = riskToLevel(riskScore);

  return `
    <tr>
      <td>${ev.ts}</td>

      <td class="mono">${ev.ip}</td>

      <td>
        ${ev.geo?.city || "-"}, ${ev.geo?.region || ""}
        <br><small>${ev.geo?.isp || ""}</small>
      </td>

      <td>${translateEvent(ev.type)}</td>

      <td>${ev.ref || "-"}</td>

      <td>${dwell ? dwell + " ms" : "-"}</td>

      <td>
        <span class="badge ${riskLevel}">
          ${riskLevel}
        </span>
      </td>

      <td>${explain(ev.type, dwell)}</td>

      <td>
        <button class="map-btn"
                onclick="openMap(${ev.geo?.lat || 0}, ${ev.geo?.lon || 0}, '${ev.geo?.city || "-"}')">
          Ver mapa
        </button>
      </td>
    </tr>
  `;
}


// ==========================
// ✅ CARGA DE DATOS (CORREGIDO)
// ==========================
async function loadData(){

  const onlySusp = document.getElementById("onlySuspicious").checked;
  const search = document.getElementById("search").value.toLowerCase();

  let events = [];

  try {
    // ✅ FIX CLAVE: URL correcta del backend
    const res = await fetch("https://clikguardian.onrender.com/api/events");
    const j = await res.json();
    events = j.events || [];
  } catch (err){
    console.error("Error cargando eventos:", err);
  }

  // Filtrar sospechosos
  if (onlySusp) {
    events = events.filter(ev => riskToLevel(ev.risk?.score ?? 0) !== "bajo");
  }

  // Filtro de búsqueda
  if (search){
    events = events.filter(ev =>
      (ev.ip || "").toLowerCase().includes(search) ||
      (ev.geo?.city || "").toLowerCase().includes(search) ||
      (ev.geo?.region || "").toLowerCase().includes(search) ||
      (ev.geo?.isp || "").toLowerCase().includes(search) ||
      (ev.type || "").toLowerCase().includes(search)
    );
  }

  // Pintar tabla
  document.getElementById("tbody").innerHTML =
    events.map(renderRow).join("");

  // KPI
  document.getElementById("kpiSummary").innerText =
    `Total: ${events.length}`;
}


// ==========================
// ✅ MAPA MODAL
// ==========================
let map = null;

function openMap(lat, lon, city){

  const modal = document.getElementById("mapModal");
  modal.style.display = "flex";

  if (!map){
    map = L.map('map').setView([lat, lon], 13);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png").addTo(map);
  } else {
    map.setView([lat, lon], 13);
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
