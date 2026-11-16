const API = "/api/v1";
const keyInput = document.querySelector("#api-key");
try { keyInput.value = sessionStorage.getItem("vulnprior-key") || ""; } catch (_) { /* storage unavailable */ }

const headers = (extra = {}) => (keyInput.value ? { "X-API-Key": keyInput.value, ...extra } : extra);
async function get(path) {
  const res = await fetch(`${API}${path}`, { headers: headers() });
  if (!res.ok) throw new Error(`${res.status} ${path}`);
  return res.json();
}

const esc = (v) => String(v ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;").replaceAll("'", "&#039;");
const card = (label, value, hint = "", tone = "") =>
  `<article class="card ${tone}"><span>${label}</span><strong>${value}</strong><small>${hint}</small></article>`;

function line(svgId, values, labels, max) {
  const svg = document.querySelector(svgId);
  if (values.length < 2) { svg.innerHTML = ""; return; }
  const w = 520, h = 170, pad = 18, top = max || Math.max(...values) * 1.1;
  const xs = values.map((_, i) => pad + i * (w - 2 * pad) / (values.length - 1));
  const ys = values.map(v => h - pad - (v / top) * (h - 2 * pad));
  const pts = xs.map((x, i) => `${x},${ys[i]}`).join(" ");
  svg.innerHTML = `<line x1="${pad}" y1="${h - pad}" x2="${w - pad}" y2="${h - pad}" class="axis"/>` +
    `<polyline points="${pts}" fill="none" stroke="currentColor" stroke-width="3" stroke-linejoin="round"/>` +
    xs.map((x, i) => `<circle cx="${x}" cy="${ys[i]}" r="4" fill="currentColor"><title>${esc(labels[i])}: ${values[i]}</title></circle>`).join("");
}

async function loadSummary() {
  const d = await get("/dashboard/summary");
  document.querySelector("#summary").innerHTML = [
    card("Open exposure", d.open_findings, `total risk ${d.total_exposure}`),
    card("Critical", d.critical_findings, `${d.high_findings} high`, d.critical_findings ? "bad" : ""),
    card("Overdue", d.overdue_findings, `${d.overdue_critical} critical overdue`, d.overdue_findings ? "bad" : ""),
    card("SLA compliance", `${d.sla_compliance_rate}%`, "open findings within deadline", d.sla_compliance_rate < 80 ? "warn" : "good"),
    card("Known exploited", d.kev_findings, `${d.ransomware_findings} ransomware-linked`, d.kev_findings ? "warn" : ""),
    card("MTTR", d.mttr_days ?? "–", d.remediated_within_sla_rate == null ? "days" : `days · ${d.remediated_within_sla_rate}% in SLA`),
    card("Accepted risks", d.risk_accepted_findings, `${d.acceptances_expiring_14d} expiring ≤14d`),
  ].join("");
}

async function loadCharts() {
  const [impact, trend] = await Promise.all([get("/dashboard/remediation-impact?top=3"), get("/dashboard/trend")]);
  document.querySelector("#pareto-title").textContent = `Fixing ${impact.top} findings removes ${impact.reduction_percent}% of exposure`;
  line("#pareto", impact.curve.map(c => c.cumulative_reduction_percent), impact.curve.map(c => `${c.fixed} fixed`), 100);
  document.querySelector("#pareto-text").textContent =
    `Cumulative share of the ${impact.total_exposure} risk points removed as findings are fixed in priority order.`;
  line("#trend", trend.map(s => s.total_exposure), trend.map(s => s.label));
  document.querySelector("#trend-labels").innerHTML = trend.map(s =>
    `<span>${esc(s.label)}<b>${s.total_exposure}</b><i>${s.sla_compliance}% SLA</i></span>`).join("");
}

async function loadFindings() {
  const data = await get("/findings?limit=25");
  const visible = data.filter(f => ["open", "in_progress", "mitigated"].includes(f.status));
  document.querySelector("#findings").innerHTML = visible.map(f => `
    <tr>
      <td><span class="badge ${esc(f.risk_level)}">${f.risk_score} ${esc(f.risk_level)}</span></td>
      <td>${esc(f.asset.name)}<br><small class="muted">${esc(f.asset.business_service)} · ${esc(f.asset.owner)}</small></td>
      <td>${esc(f.vulnerability.cve_id)}<br><small class="muted">CVSS ${f.vulnerability.cvss.toFixed(1)} · EPSS ${(f.vulnerability.epss * 100).toFixed(0)}%</small></td>
      <td>${f.vulnerability.kev ? '<span class="tag">KEV</span>' : ""}${f.vulnerability.ransomware_use ? '<span class="tag red">RANSOMWARE</span>' : ""}${f.asset.internet_exposed ? '<span class="tag">INTERNET</span>' : ""}</td>
      <td>${esc(f.status.replace("_", " "))}</td>
      <td>${esc(f.decision)}</td>
      <td class="${f.overdue ? "late" : ""}">${esc((f.sla_due_at || "").slice(0, 10))}${f.overdue ? " · OVERDUE" : ""}</td>
      <td>${esc(f.ticket_ref || "—")}</td>
    </tr>`).join("");
  document.querySelector("#explanation").textContent = visible.length ? `Why #1: ${visible[0].explanation}` : "No open finding. Run the demo seed script.";
}

async function loadBusiness() {
  const [services, plan] = await Promise.all([get("/dashboard/business-services"), get("/reports/remediation-plan")]);
  document.querySelector("#services").innerHTML = services.map(s => `
    <tr><td>${esc(s.business_service)}</td><td><b>${s.exposure}</b></td><td>${s.critical}</td>
    <td class="${s.overdue ? "late" : ""}">${s.overdue}</td><td>${s.known_exploited}</td><td>${esc(s.owners.join(", "))}</td></tr>`).join("");
  document.querySelector("#plan").innerHTML = plan.map(g => `
    <div class="row-card"><div><strong>${esc(g.owner)}</strong>
    <span>${g.items.slice(0, 3).map(i => `${esc(i.cve_id)} on ${esc(i.asset)}`).join(" · ")}</span></div>
    <span class="count ${g.overdue_items ? "late" : ""}">${g.open_items} open · ${g.overdue_items} overdue</span></div>`).join("");
}

async function loadAudit() {
  try {
    const chain = await get("/audit/verify");
    const el = document.querySelector("#chain-status");
    el.textContent = chain.valid ? `✔ decision log verified (${chain.events_checked})` : `✖ log broken at #${chain.first_broken_event_id}`;
    el.className = `pill ${chain.valid ? "ok" : "ko"}`;
  } catch (_) { /* role without audit access */ }
}

async function simulate() {
  const form = document.querySelector("#sim");
  const body = {};
  for (const el of form.elements) {
    if (!el.name) continue;
    body[el.name] = el.type === "checkbox" ? el.checked : el.type === "number" ? Number(el.value) : el.value;
  }
  const res = await fetch(`${API}/dashboard/risk-preview`, { method: "POST", headers: headers({ "Content-Type": "application/json" }), body: JSON.stringify(body) });
  const r = await res.json();
  if (!res.ok) { document.querySelector("#sim-result").textContent = "Invalid input"; return; }
  const factors = Object.entries(r.factors).filter(([, v]) => v !== 0)
    .map(([k, v]) => `<li><span>${esc(k.replaceAll("_", " "))}</span><b>${v > 0 ? "+" : ""}${v}</b></li>`).join("");
  document.querySelector("#sim-result").innerHTML = `
    <span class="badge ${esc(r.level)} big">${r.score} ${esc(r.level)}</span>
    <p><b>${esc(r.decision)}</b> · SLA ${r.sla_hours}h</p><ul class="factors">${factors}</ul>`;
}

async function refresh() {
  try {
    await Promise.all([loadSummary(), loadCharts(), loadFindings(), loadBusiness(), loadAudit(), simulate()]);
  } catch (error) {
    document.querySelector("#explanation").textContent = `Unable to load dashboard: ${error.message}`;
  }
}

keyInput.addEventListener("change", () => { try { sessionStorage.setItem("vulnprior-key", keyInput.value); } catch (_) { /* ignore */ } refresh(); });
document.querySelector("#sim").addEventListener("input", simulate);
document.querySelector("#refresh").addEventListener("click", refresh);
refresh();
