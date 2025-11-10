// ==========================
// ✅ TRADUCCIÓN A LENGUAJE HUMANO
// ==========================
function explain(event, dwell) {

  if(event === "land")
    return "Entró a la página";

  if(event === "whatsapp_click")
    return "Hizo clic real en el botón de WhatsApp";

  if(event === "leave") {
    if(!dwell) return "Salió rápidamente";
    if(dwell < 800) return "Se fue en menos de 1 segundo (posible bot o clic inválido)";
    if(dwell < 3000) return "Visitó la página pero se retiró rápido";
    return "Estuvo navegando por la página con normalidad";
  }

  return "Actividad detectada";
}


// ==========================
// ✅ FUNCIONES DE TABLA
// ==========================
function renderRow(r){
  const dwell = r.dwell_ms ?? 0;

  return `
    <tr>
      <td>${r.ts}</td>
      <td class="mono">${r.ip}</td>
      <td>${r.city || "-"}, ${r.region || ""}<br>
          <small>${r.isp || ""}</small>
      </td>
      <td>${r.type}</td>
      <td>${r.ref || "-"}</td>
      <td>${dwell ? dwell + " ms" : "-"}</td>

      <td><span class="badge ${r.risk_level}">${r.risk_level}</span></td>

      <td>${explain(r.type, dwell)}</td>

      <td>
        <button class="map-btn" onclick="openMap('${r.lat}','${r.lon}','${r.city}')">Ver mapa</button>
      </td>
    </tr>
  `;
}


// ==========================
// ✅ OBTENER DATOS DEL SERVIDOR
// ==========================
async function loadData(){
  const onlySuspicious = document.getElementById("onlySuspicious").checked;
  const search = document.getElementById("search").value.toLowerCase();

  let data = [];
  try {
    const res = await fetch("/api/events");
    data = await res.json();
  } catch (e) {}

  if(onlySuspicious) {
    data = data.filter(x => x.risk_level === "alto" || x.risk_level === "medio");
  }

  if(search){
    data = data.filter(x =>
      (x.ip || "").toLowerCase().includes(search) ||
      (x.city || "").toLowerCase().includes(search) ||
      (x.region || "").toLowerCase().includes(search) ||
      (x.isp || "").toLowerCase().includes(search) ||
      (x.type || "").toLowerCase().includes(search)
    );
  }

  document.getElementById("tbody").innerHTML =
    data.map(renderRow).join("");

  // KPIs
  document.getElementById("kpiSummary").innerText =
    `Total: ${data.length}`;
}


// ==========================
// ✅ MAPA MODAL
// ==========================
let map = null;

function openMap(lat, lon, city){
  const modal = document.getElementById("mapModal");
  modal.style.display = "flex";

  if(!map){
    map = L.map('map').setView([lat,lon], 12);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{}).addTo(map);
  } else {
    map.setView([lat,lon], 12);
  }

  L.marker([lat,lon]).addTo(map);
  document.getElementById("mapTitle").innerText = "Ubicación aproximada: " + city;
}

document.getElementById("closeMap").onclick = () =>
  document.getElementById("mapModal").style.display = "none";

document.getElementById("zoomIn").onclick = () => map.zoomIn();
document.getElementById("zoomOut").onclick = () => map.zoomOut();


// ==========================
// ✅ AUTO CARGA
// ==========================
loadData();
document.getElementById("refresh").onclick = loadData;
setInterval(loadData, 5000);
