// static/app.js
const tbody = document.getElementById("tbody");
const onlySusp = document.getElementById("onlySuspicious");
const search = document.getElementById("search");
const btnRefresh = document.getElementById("refresh");
const kpis = document.getElementById("kpis");

function badge(score) {
  if (score >= 80) return '<span class="badge alto">Alto</span>';
  if (score >= 40) return '<span class="badge medio">Medio</span>';
  return '<span class="badge bajo">Bajo</span>';
}

function row(ev) {
  const geo = ev.geo || {};
  const risk = ev.risk || { score: 0, reasons: [] };
  const city = geo.city || "-";
  const region = geo.region || "-";
  const isp = geo.org || "-";
  const ua = ev.ua || "-";
  const ref = ev.ref || "-";
  const dwell = ev.dwell_ms != null ? `${Math.round(ev.dwell_ms)} ms` : "-";
  const razon = (risk.reasons || []).join(" · ");

  return `
  <tr>
    <td>${new Date(ev.ts).toLocaleString()}</td>
    <td class="mono">${ev.ip}</td>
    <td>${city} / ${region}<br><span class="mono" style="opacity:.7">${isp}</span></td>
    <td title="${ua}">${ua.substring(0, 48)}${ua.length>48?"…":""}</td>
    <td>${ref}</td>
    <td>${dwell}</td>
    <td>${badge(risk.score)}<br><small>${razon || "-"}</small></td>
    <td>
      <button class="danger" onclick="blockIP('${ev.ip}')">Bloquear IP</button>
    </td>
  </tr>`;
}

async function fetchEvents() {
  const r = await fetch("/api/events?limit=300");
  const j = await r.json();
  let list = j.events || [];

  const q = (search.value || "").toLowerCase().trim();
  if (q) {
    list = list.filter(e => {
      const geo = e.geo || {};
      const hay = [
        e.ip, e.ua, e.ref, (geo.city||""), (geo.region||""), (geo.org||"")
      ].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }
  if (onlySusp.checked) {
    list = list.filter(e => (e.risk && e.risk.score >= 80));
  }

  tbody.innerHTML = list.map(row).join("");

  // KPIs
  const total = j.events?.length || 0;
  const suspicious = j.events?.filter(e => e.risk && e.risk.score >= 80).length || 0;
  const fast = j.events?.filter(e => (e.dwell_ms || 0) < 800).length || 0;
  kpis.innerHTML = `
    <div class="badge">Total: ${total}</div>
    <div class="badge alto">Sospechosos: ${suspicious}</div>
    <div class="badge medio">Dwell < 800ms: ${fast}</div>
  `;
}

async function blockIP(ip) {
  await fetch("/api/blocklist", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ ip })
  });
  fetchEvents();
}

btnRefresh?.addEventListener("click", fetchEvents);
onlySusp?.addEventListener("change", fetchEvents);
search?.addEventListener("input", () => {
  // filtra en vivo sin pedir al server
  fetchEvents();
});

fetchEvents();
setInterval(fetchEvents, 20000);
