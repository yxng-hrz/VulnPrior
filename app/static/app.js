const api = "/api/v1";

function card(label, value) {
  return `<article class="card"><span>${label}</span><strong>${value}</strong></article>`;
}

async function loadSummary() {
  const res = await fetch(`${api}/dashboard/summary`);
  const data = await res.json();
  document.querySelector("#summary").innerHTML = [
    card("Open findings", data.open_findings),
    card("Critical", data.critical_findings),
    card("Known exploited", data.kev_findings),
    card("Average risk", `${data.average_risk_score}/100`),
  ].join("");
}

async function loadFindings() {
  const res = await fetch(`${api}/findings?limit=20`);
  const data = await res.json();
  const tbody = document.querySelector("#findings");
  tbody.innerHTML = data.map(item => `
    <tr>
      <td><span class="badge ${item.risk_level}">${item.risk_score} ${item.risk_level}</span></td>
      <td>${item.asset.name}</td>
      <td>${item.vulnerability.cve_id}</td>
      <td>${item.vulnerability.cvss.toFixed(1)}</td>
      <td>${(item.vulnerability.epss * 100).toFixed(1)}%</td>
      <td>${item.vulnerability.kev ? "YES" : "NO"}</td>
      <td>${item.decision}</td>
      <td>${item.sla_hours}h</td>
    </tr>
  `).join("");

  document.querySelector("#explanation").textContent =
    data.length ? data[0].explanation : "No finding yet. Run the demo seed script.";
}

async function refresh() {
  await Promise.all([loadSummary(), loadFindings()]);
}

document.querySelector("#refresh").addEventListener("click", refresh);
refresh();
