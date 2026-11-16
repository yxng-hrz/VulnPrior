from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session, joinedload

from app.models import Finding, RiskSnapshot
from app.services.audit import verify_chain
from app.services.finding_service import (
    EXPOSED_STATUSES, as_aware, business_service_exposure, governance_metrics, is_overdue, remediation_impact,
)


def take_snapshot(db: Session, label: str = "", created_at: datetime | None = None) -> RiskSnapshot:
    metrics = governance_metrics(db)
    critical = db.query(Finding).filter(Finding.status.in_(EXPOSED_STATUSES), Finding.risk_level == "CRITICAL").count()
    snapshot = RiskSnapshot(
        label=label, open_findings=metrics["exposed_findings"], critical_findings=critical,
        overdue_findings=metrics["overdue_findings"], total_exposure=metrics["total_exposure"],
        sla_compliance=metrics["sla_compliance_rate"],
    )
    if created_at is not None:
        snapshot.created_at = created_at
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def trend(db: Session, limit: int = 12) -> list[RiskSnapshot]:
    return list(reversed(db.query(RiskSnapshot).order_by(RiskSnapshot.created_at.desc()).limit(limit).all()))


def executive_report(db: Session) -> str:
    now = datetime.now(timezone.utc)
    m = governance_metrics(db)
    services = business_service_exposure(db)
    impact = remediation_impact(db, top=5)
    history = trend(db, 6)
    chain = verify_chain(db)
    findings = db.query(Finding).options(joinedload(Finding.asset), joinedload(Finding.vulnerability)).all()
    exposed = sorted([f for f in findings if f.status in EXPOSED_STATUSES], key=lambda f: f.risk_score, reverse=True)
    accepted = [f for f in findings if f.status == "risk_accepted"]
    critical = [f for f in exposed if f.risk_level == "CRITICAL"]
    ransomware = [f for f in exposed if f.vulnerability.ransomware_use]

    lines = [
        "# Vulnerability Risk — Executive Report",
        "",
        f"_Generated {now.strftime('%Y-%m-%d %H:%M UTC')} by VulnPrior. Synthetic demo data._",
        "",
        "## 1. Headline",
        "",
        f"- **Open exposure:** {m['exposed_findings']} findings, {len(critical)} critical, total risk {m['total_exposure']}",
        f"- **SLA compliance:** {m['sla_compliance_rate']}% — **{m['overdue_findings']} overdue** ({m['overdue_critical']} critical)",
        f"- **Mean time to remediate:** {m['mttr_days'] if m['mttr_days'] is not None else 'n/a'} days"
        + (f" | remediated within SLA: {m['remediated_within_sla_rate']}%" if m['remediated_within_sla_rate'] is not None else ""),
        f"- **Ransomware-linked vulnerabilities still open:** {len(ransomware)}",
        f"- **Quick win:** fixing the top 5 findings removes **{impact['reduction_percent']}%** of total exposure",
        f"- **Decision log integrity:** {'verified' if chain['valid'] else 'BROKEN — investigate'} ({chain['events_checked']} events)",
        "",
    ]
    if len(history) >= 2:
        lines += ["## 2. Trend", "", "| Snapshot | Open | Critical | Overdue | Exposure | SLA compliance |", "|---|---:|---:|---:|---:|---:|"]
        for s in history:
            label = s.label or as_aware(s.created_at).strftime("%Y-%m-%d")
            lines.append(f"| {label} | {s.open_findings} | {s.critical_findings} | {s.overdue_findings} | {s.total_exposure} | {s.sla_compliance}% |")
        lines.append("")

    lines += ["## 3. Business services most at risk", ""]
    if services:
        lines += ["| Business service | Exposure | Critical | Overdue | Known exploited | Owners |", "|---|---:|---:|---:|---:|---|"]
        for s in services[:6]:
            lines.append(f"| {s['business_service']} | {s['exposure']} | {s['critical']} | {s['overdue']} | {s['known_exploited']} | {', '.join(s['owners'])} |")
    else:
        lines.append("No open exposure.")
    lines += ["", "## 4. Top findings", "", "| Risk | Asset | CVE | Why | Deadline |", "|---:|---|---|---|---|"]
    for f in exposed[:8]:
        why = f.explanation.split("Key factors: ")[-1].split(". Target")[0]
        flag = " (overdue)" if is_overdue(f, now) else ""
        lines.append(f"| {f.risk_score} {f.risk_level} | {f.asset.name} | {f.vulnerability.cve_id} | {why} | {as_aware(f.sla_due_at).strftime('%Y-%m-%d')}{flag} |")

    soon = now + timedelta(days=30)
    lines += ["", "## 5. Accepted risks", ""]
    if accepted:
        for f in accepted:
            until = as_aware(f.accepted_until)
            marker = " — expires within 30 days" if until and until <= soon else ""
            lines.append(f"- {f.vulnerability.cve_id} on {f.asset.name}: accepted by {f.accepted_by} until {until.date().isoformat() if until else 'n/a'}{marker}. {f.acceptance_justification}")
    else:
        lines.append("- None.")

    asks = []
    if m["overdue_critical"]:
        asks.append(f"Escalate the {m['overdue_critical']} overdue critical findings to their business owners this week.")
    if ransomware:
        asks.append("Treat ransomware-linked vulnerabilities as an emergency change; approve out-of-cycle maintenance windows.")
    if impact["reduction_percent"] >= 40:
        asks.append(f"Fund a focused sprint on the top 5 findings ({impact['reduction_percent']}% of exposure).")
    if m["acceptances_expiring_14d"]:
        asks.append("Risk owners to renew or close acceptances expiring within 14 days.")
    if not asks:
        asks.append("No escalation required; maintain the remediation cadence.")
    lines += ["", "## 6. Decisions requested", ""] + [f"{i}. {a}" for i, a in enumerate(asks, 1)]
    lines += ["", "---", "_Explainable portfolio scoring model; see /api/v1/dashboard/methodology._", ""]
    return "\n".join(lines)
