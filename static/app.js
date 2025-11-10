async function loadEvents() {
  let r = await fetch("/api/events");
  let data = await r.json();
  return data.events || [];
}

function badge(score) {
  if (score >= 80) return `<span class="badge alto">Alto</span>`;
  if (score >= 40) return `<span class="badge medio">Medio</span>`;
  return `<span class="badge bajo">Bajo</span>`;
}

function row(ev) {
  let geo = ev.geo || {};
  let city = geo.city || "—";
  let loc  = geo.locality || geo.region || "—";
  let isp  = geo.org || "—";
  let ref  = ev.ref || "—";
  let ua   = ev.ua || "—";
  let dw   = ev.dwell_ms ? ev.dwell_ms + " ms" : "—";

  let blocked = ev.blocked ? `<span class="badge alto">Bloqueado</span>` : "";

  return `
  <tr>
    <td>${ev.ts.split("T")[1].substring(0,8)}</td>
    <td><span class="mono">${ev.ip}</span><br><small>${isp}</small></td>
    <td>${city}<br><small>${loc}</small></td>
    <td><small>${ua}</small></td>
    <td>${ref}</td>
    <td>${dw}</td>
    <td>${badge(ev.fraud_score || 0)}</td>
    <td>
      ${blocked}
      <button onclick="blockIP('${ev.ip}')">Bloquear</button>
      <button class="danger" onclick="unblockIP('${ev.ip}')">Quitar</button>
    </td>
  </tr>`
}

async function blockIP(ip) {
  await fetch("/api/blocklist", {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({ip})
  });
  refresh();
}

async function unblockIP(ip) {
  await fetch("/api/blocklist", {
    method:"DELETE",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({ip})
  });
  refresh();
}

async function exportBlocked() {
  window.location.href = "/export/blocklist.csv";
}

async function refresh() {
  let evs = await loadEvents();
  let tbody = document.getElementById("tbody");
  let search = document.getElementById("search").value.toLowerCase();
  let suspiciousOnly = document.getElementById("onlySuspicious").checked;

  tbody.innerHTML = "";

  evs.forEach(ev => {
    if (suspiciousOnly && !ev.suspect) return;
    let txt = JSON.stringify(ev).toLowerCase();
    if (search && !txt.includes(search)) return;
    tbody.innerHTML += row(ev);
  });
}

document.getElementById("refresh").onclick = refresh;
document.getElementById("exportIPs").onclick = exportBlocked;
document.getElementById("search").oninput = refresh;
document.getElementById("onlySuspicious").onchange = refresh;

refresh();
