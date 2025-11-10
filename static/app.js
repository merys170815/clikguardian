// ===============================
//  VARIABLES
// ===============================
const tbody = document.getElementById('tbody');
const refreshBtn = document.getElementById('refresh');
const onlySuspicious = document.getElementById('onlySuspicious');
const searchInput = document.getElementById('search');
const kpiSummary = document.getElementById('kpiSummary');

let events_cache = [];

// ===============================
//  MAPA
// ===============================
const modal = document.getElementById('mapModal');
const closeMapBtn = document.getElementById('closeMap');
let map, marker, circle;

function openMap(lat, lon, title = '', radiusMeters = 300) {
  modal.style.display = 'flex';
  setTimeout(() => {
    if(!map) {
      map = L.map('map').setView([lat || 0, lon || 0], lat ? 15 : 2);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19
      }).addTo(map);
    } else {
      map.invalidateSize();
      map.setView([lat || 0, lon || 0], lat ? 15 : 2);
    }

    if(marker) map.removeLayer(marker);
    if(circle) map.removeLayer(circle);

    if(lat && lon) {
      marker = L.marker([lat, lon]).addTo(map).bindPopup(title);
      circle = L.circle([lat, lon], { radius: radiusMeters, color: '#2bffbc', fillColor: '#2bffbc', fillOpacity: 0.15 }).addTo(map);
      map.fitBounds(circle.getBounds(), { padding: [20,20] });
    }
  }, 100);
}

closeMapBtn.addEventListener('click', () => {
  modal.style.display = 'none';
});

document.getElementById('zoomIn').addEventListener('click', ()=> map && map.zoomIn());
document.getElementById('zoomOut').addEventListener('click', ()=> map && map.zoomOut());

// ===============================
//  CARGA DE EVENTOS
// ===============================
async function loadEvents() {
  try {
    const res = await fetch('/api/events?limit=300');
    const j = await res.json();
    events_cache = j.events || [];
    renderTable();
    renderKPIs();
  } catch(e) {
    console.error('Error cargando eventos', e);
  }
}

// ===============================
//  KPIs
// ===============================
function renderKPIs(){
  const total = events_cache.length;
  const suspicious = events_cache.filter(e => e.risk?.suspicious).length;
  const whatsapp = events_cache.filter(e => e.type === "whatsapp").length;

  kpiSummary.textContent = `Total: ${total} · Sospechosos: ${suspicious} · WhatsApp: ${whatsapp}`;
}

// ===============================
//  TABLA
// ===============================
function renderTable(){
  const q = searchInput.value.trim().toLowerCase();
  const showSusp = onlySuspicious.checked;

  tbody.innerHTML = '';

  events_cache.forEach(ev => {
    const geo = ev.geo || {};
    const city = geo.city || '-';
    const region = geo.region || '-';
    const isp = geo.isp || '-';
    const lat = geo.lat || 0;
    const lon = geo.lon || 0;

    // FILTRO
    const text = `${ev.ip} ${city} ${region} ${isp} ${ev.ref || ''} ${ev.type || ''}`.toLowerCase();
    if(q && !text.includes(q)) return;
    if(showSusp && !(ev.risk?.suspicious)) return;

    const tr = document.createElement('tr');

    tr.innerHTML = `
      <td>${ev.ts ? new Date(ev.ts).toLocaleString() : '-'}</td>
      <td class="mono">${ev.ip || '-'}</td>
      <td>
        <strong>${city}</strong><br>
        <span style="color:#9aa5b1;font-size:12px">${region} · ${isp}</span>
      </td>
      <td>${ev.type || '-'}</td>
      <td>${ev.ref || ev.url || '-'}</td>
      <td>${ev.dwell_ms ? ev.dwell_ms + ' ms' : '-'}</td>
      <td>
        <span class="badge ${ev.risk?.score >= 80 ? 'alto' : ev.risk?.score >= 40 ? 'medio' : 'bajo'}">
          ${ev.risk?.score || 0}
        </span>
      </td>
    `;

    // ACCIONES
    const actionTd = document.createElement('td');

    const mapBtn = document.createElement('button');
    mapBtn.className = 'map-btn';
    mapBtn.textContent = 'Mapa';
    mapBtn.onclick = () => openMap(Number(lat), Number(lon), `${ev.ip} · ${city}`, 400);
    actionTd.appendChild(mapBtn);

    const blockBtn = document.createElement('button');
    blockBtn.className = 'danger';
    blockBtn.style.marginLeft = '8px';
    blockBtn.textContent = 'Bloquear';
    blockBtn.onclick = async () => {
      await fetch('/api/blocklist', {
        method:'POST',
        headers:{ 'Content-Type':'application/json' },
        body: JSON.stringify({ ip: ev.ip })
      });
      alert("IP bloqueada");
      loadEvents();
    };
    actionTd.appendChild(blockBtn);

    tr.appendChild(actionTd);
    tbody.appendChild(tr);
  });
}

// ===============================
//  EVENTOS UI
// ===============================
refreshBtn.addEventListener('click', loadEvents);
searchInput.addEventListener('input', renderTable);
onlySuspicious.addEventListener('change', renderTable);

// ===============================
//  INICIO
// ===============================
loadEvents();
