// =============================================
// ✅ ClickGuardian Dashboard JS
// =============================================

async function loadEvents() {
  try {
    const onlySuspicious = document.getElementById("onlySuspicious").checked;
    const search = document.getElementById("search").value.toLowerCase();

    const resp = await fetch("/api/events");
    const json = await resp.json();
    let rows = json.events || [];

    // Filtro "solo sospechosos"
    if (onlySuspicious) {
      rows = rows.filter(ev => (ev.risk || 0) >= 60);
    }

    // Filtro de búsqueda
    if (search) {
      rows = rows.filter(ev =>
        JSON.stringify(ev).toLowerCase().includes(search)
      );
    }

    // Renderizado tabla
    const tbody = document.getElementById("tbody");
    tbody.innerHTML = "";

    rows.forEach(ev => {
      tbody.innerHTML += row(ev);
    });

    // Actualizar KPIs
    updateKPIs(rows);

  } catch (e) {
    console.error("❌ Error cargando eventos:", e);
  }
}

// =============================================
// ✅ Genera un badge (Riesgo)
// =============================================
function badge(score) {
  if (score >= 80) return `<span class="badge alto">Alto</span>`;
  if (score >= 40) return `<span class="badge medio">Medio</span>`;
  return `<span class="badge bajo">Bajo</span>`;
}

// =============================================
// ✅ Render de cada fila de la tabla
// =============================================
function row(ev) {
  let geo = ev.geo || {};
  let city = geo.city || geo.region || "--";
  let loc = geo.locality || "--";
  let isp = geo.org || "--";
  let ua = ev.ua || "--";
  let ref = ev.ref || "--";
  let dw = ev.dwell_ms ? ev.dwell_ms + " ms" : "--";

  return `
    <tr>
      <td>${ev.ts}</td>
      <td>${ev.ip}</td>
      <td>${city}</td>
      <td class="mono">${ua}</td>
      <td>${ref}</td>
      <td>${dw}</td>
      <td>${badge(ev.risk || 0)}</td>
      <td>
        <button onclick="blockIP('${ev.ip}')">Bloquear</button>
      </td>
    </tr>
  `;
}

// =============================================
// ✅ KPIs (arriba de la tabla)
// =============================================
function updateKPIs(rows) {
  const total = rows.length;
  const suspicious = rows.filter(r => (r.risk || 0) >= 60).length;

  document.getElementById("kpis").innerHTML = `
    <div class="badge bajo">Total: ${total}</div>
    <div class="badge alto">Sospechosos: ${suspicious}</div>
  `;
}

// =============================================
// ✅ Enviar IP al backend para bloquear
// =============================================
async function blockIP(ip) {
  if (!confirm(`¿Seguro que deseas bloquear la IP ${ip}?`)) return;

  await fetch("/api/blocklist", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ ip })
  });

  loadEvents();
}

// =============================================
// ✅ Asignar eventos a los botones
// =============================================
document.getElementById("refresh").onclick = loadEvents;
document.getElementById("onlySuspicious").onclick = loadEvents;
document.getElementById("search").oninput = loadEvents;

// ✅ Carga inicial
loadEvents();
