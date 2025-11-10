// static/app.js
const tbody = document.getElementById('tbody');
const refreshBtn = document.getElementById('refresh');
const onlySuspicious = document.getElementById('onlySuspicious');
const searchInput = document.getElementById('search');
const kpiSummary = document.getElementById('kpiSummary');

let events_cache = [];

// Modal + Leaflet
const modal = document.getElementById('mapModal');
const closeMapBtn = document.getElementById('closeMap');
let map, marker, circle;

function openMap(lat, lon, title = '', radiusMeters = 300) {
  modal.style.display = 'flex';
  setTimeout(() => {
    if(!map) {
      map = L.map('map', {zoomControl:false}).setView([lat || 0, lon || 0], lat?15:2);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom: 19}).addTo(map);
    } else {
      map.invalidateSize();
      map.setView([lat || 0, lon || 0], lat?15:2);
    }
    if(marker) map.removeLayer(marker);
    if(circle) map.removeLayer(circle);
    if(lat && lon) {
      marker = L.marker([lat, lon]).addTo(map).bindPopup(title);
      circle = L.circle([lat, lon], { radius: radiusMeters, color: '#2bffbc', fillColor: '#2bffbc', fillOpacity: 0.15 }).addTo(map);
      map.fitBounds(circle.getBounds(), { padding: [20,20] });
    }
  }, 50);
}
document.getElementById('zoomIn').addEventListener('click', ()=> map && map.zoomIn());
document.getElementById('zoomOut').addEventListener('click', ()=> map && map.zoomOut());
closeMapBtn.addEventListener('click', () => { modal.style.display = 'none'; });

async function loadEvents() {
  try {
    const res = await fetch('/api/events?limit=300');
    const j = await res.json();
    events_cache = j.events || [];
    renderTable();
    renderKPIs();
  } catch(err) {
    console.error('Error cargando eventos', err);
  }
}

function renderKPIs(){
  const total = events_cache.length;
  const suspicious = events_cache.filter(e => e.risk && e.risk.suspicious).length;
  const dwellSmall = events_cache.filter(e => e.dwell_ms && e.dwell_ms < 800).length;
  kpiSummary.innerText = `Total: ${total} · Sospechosos: ${suspicious} · Dwell <800ms: ${dwellSmall}`;
}

function renderTable(){
  const q = (searchInput.value || '').trim().toLowerCase();
  const onlyS = !!onlySuspicious.checked;
  tbody.innerHTML = '';

  events_cache.forEach(ev => {
    const geo = ev.geo || {};
    const city = geo.city || '-';
    const region = geo.region || '-';
    const isp = geo.isp || geo.org || geo.orgname || '-';
    const lat = Number(geo.lat || geo.latitude || 0);
    const lon = Number(geo.lon || geo.longitude || 0);
    const evt = ev.type || '-';

    const rowText = `${ev.ip || ''} ${city} ${region} ${isp} ${evt} ${(ev.ref||'')} ${(ev.url||'')}`.toLowerCase();
    if(q && !rowText.includes(q)) return;
    if(onlyS && !(ev.risk && ev.risk.suspicious)) return;

    const tr = document.createElement('tr');

    const tsTd = document.createElement('td');
    tsTd.textContent = ev.ts ? new Date(ev.ts).toLocaleString() : '-';
    tr.appendChild(tsTd);

    const ipTd = document.createElement('td');
    ipTd.innerHTML = `<span class="mono">${ev.ip || '-'}</span>`;
    tr.appendChild(ipTd);

    const cityTd = document.createElement('td');
    cityTd.innerHTML = `<strong>${city}</strong><div style="color:#9aa5b1;font-size:12px">${region} · ${isp}</div>`;
    tr.appendChild(cityTd);

    const typeTd = document.createElement('td');
    typeTd.textContent = evt;
    tr.appendChild(typeTd);

    const refTd = document.createElement('td');
    refTd.textContent = ev.ref || ev.url || '-';
    tr.appendChild(refTd);

    const dwellTd = document.createElement('td');
    dwellTd.textContent = ev.dwell_ms ? `${ev.dwell_ms} ms` : '-';
    tr.appendChild(dwellTd);

    const riskTd = document.createElement('td');
    const score = ev.risk && ev.risk.score ? ev.risk.score : 0;
    let badge = 'bajo'; if(score >= 80) badge = 'alto'; else if(score >= 40) badge = 'medio';
    const reasons = (ev.risk && ev.risk.reasons && ev.risk.reasons.length) ? ev.risk.reasons.join(', ') : '';
    riskTd.innerHTML = `<span class="badge ${badge}">${score}${reasons ? ` (${reasons})` : ''}</span>`;
    tr.appendChild(riskTd);

    const actionTd = document.createElement('td');
    const mapBtn = document.createElement('button');
    mapBtn.className = 'map-btn'; mapBtn.textContent = 'Mapa';
    mapBtn.onclick = () => openMap(lat, lon, `${ev.ip || ''} · ${city}`, 300);
    actionTd.appendChild(mapBtn);

    const blockBtn = document.createElement('button');
    blockBtn.textContent = 'Bloquear IP'; blockBtn.style.marginLeft = '8px'; blockBtn.className = 'danger';
    blockBtn.onclick = async () => {
      try {
        await fetch('/api/blocklist', { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ ip: ev.ip })});
        await loadEvents();
        alert('IP bloqueada.');
      } catch(e){ console.error(e); alert('Error bloqueando'); }
    };
    actionTd.appendChild(blockBtn);

    tr.appendChild(actionTd);
    tbody.appendChild(tr);
  });
}

refreshBtn.addEventListener('click', loadEvents);
searchInput.addEventListener('input', renderTable);
onlySuspicious.addEventListener('change', renderTable);
loadEvents();
