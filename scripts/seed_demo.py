"""Seed a synthetic vulnerability backlog that exercises every governance feature offline.

CVE identifiers in the 2026-1xxxx range are synthetic. To try live threat intelligence,
import data/sample_scan_real_cves.csv and call /api/v1/enrichment/kev and /api/v1/enrichment/epss.
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import Asset, Finding, RiskSnapshot, Vulnerability  # noqa: E402
from app.services.audit import log_event  # noqa: E402
from app.services.finding_service import change_status, score_finding  # noqa: E402
from app.services.report_service import take_snapshot  # noqa: E402

NOW = datetime.now(timezone.utc)

ASSETS = [
    ("customer-portal-prod", "Digital", "production", 5, True, True, "Customer Portal"),
    ("payment-gateway-prod", "Digital", "production", 5, True, True, "Payments"),
    ("finance-api-prod", "Finance IT", "production", 5, False, True, "Finance"),
    ("vpn-gateway", "IT", "production", 5, True, False, "Remote Access"),
    ("hr-app", "HR IT", "production", 4, False, True, "Human Resources"),
    ("internal-wiki", "IT", "production", 2, False, False, "Collaboration"),
    ("staging-api", "Platform", "staging", 2, True, False, "Engineering"),
    ("dev-ci-runner", "Platform", "development", 3, True, False, "Software Delivery"),
]

# cve, title, cvss, epss, kev, ransomware, patch
VULNS = [
    ("CVE-2026-10001", "Demo remote code execution in web framework", 9.8, 0.91, True, True, True),
    ("CVE-2026-10002", "Demo authentication bypass in API gateway", 8.8, 0.62, False, False, True),
    ("CVE-2026-10003", "Demo information disclosure", 6.5, 0.08, False, False, False),
    ("CVE-2026-10004", "Demo privilege escalation in OS kernel", 7.8, 0.35, True, False, False),
    ("CVE-2026-10005", "Demo SSL VPN pre-auth overflow", 9.6, 0.88, True, True, True),
    ("CVE-2026-10006", "Demo deserialization in HR suite", 8.1, 0.21, False, False, True),
    ("CVE-2026-10007", "Demo XSS in collaboration tool", 5.4, 0.03, False, False, True),
    ("CVE-2026-10008", "Demo denial of service", 5.9, 0.04, False, False, False),
]

# asset, cve, detected days ago, status, extra
FINDINGS = [
    ("customer-portal-prod", "CVE-2026-10001", 1, "open", {"ticket_ref": "SEC-1042"}),
    ("payment-gateway-prod", "CVE-2026-10002", 12, "in_progress", {"ticket_ref": "SEC-1031"}),
    ("vpn-gateway", "CVE-2026-10005", 4, "open", {}),
    ("finance-api-prod", "CVE-2026-10004", 9, "mitigated", {"compensating_control": "Kernel module blacklisted; EDR rule deployed"}),
    ("hr-app", "CVE-2026-10006", 40, "open", {}),
    ("customer-portal-prod", "CVE-2026-10003", 25, "open", {}),
    ("internal-wiki", "CVE-2026-10007", 60, "risk_accepted", {}),
    ("staging-api", "CVE-2026-10002", 20, "remediated", {"fix_after_days": 5}),
    ("dev-ci-runner", "CVE-2026-10001", 30, "remediated", {"fix_after_days": 3}),
    ("finance-api-prod", "CVE-2026-10002", 45, "remediated", {"fix_after_days": 12}),
    ("internal-wiki", "CVE-2026-10008", 15, "false_positive", {}),
]


def seed():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        assets = {}
        for name, owner, env, crit, exposed, sensitive, service in ASSETS:
            assets[name] = Asset(name=name, owner=owner, environment=env, criticality=crit, internet_exposed=exposed,
                                 contains_sensitive_data=sensitive, business_service=service)
        vulns = {}
        for cve, title, cvss, epss, kev, ransomware, patch in VULNS:
            vulns[cve] = Vulnerability(cve_id=cve, title=title, description="Synthetic demo vulnerability.", cvss=cvss,
                                       epss=epss, kev=kev, ransomware_use=ransomware, patch_available=patch)
        db.add_all(list(assets.values()) + list(vulns.values()))
        db.flush()
        log_event(db, "demo_seeded", actor="seed", details="synthetic backlog")

        for asset, cve, days_ago, status, extra in FINDINGS:
            finding = Finding(asset=assets[asset], vulnerability=vulns[cve], detected_at=NOW - timedelta(days=days_ago),
                              ticket_ref=extra.get("ticket_ref", ""), compensating_control=extra.get("compensating_control", ""))
            score_finding(finding)
            db.add(finding)
            db.flush()
            if status == "in_progress":
                change_status(db, finding, status="in_progress", actor="secops@demo.local")
            elif status == "mitigated":
                change_status(db, finding, status="mitigated", actor="secops@demo.local")
            elif status == "risk_accepted":
                change_status(db, finding, status="risk_accepted", actor="secops@demo.local",
                              reason="Low-value internal tool scheduled for decommissioning next quarter",
                              approved_by="cio@demo.local", accepted_until=NOW + timedelta(days=10))
            elif status == "false_positive":
                change_status(db, finding, status="false_positive", actor="secops@demo.local",
                              reason="Vulnerable module not loaded; confirmed by vendor advisory")
            elif status == "remediated":
                change_status(db, finding, status="remediated", actor="secops@demo.local")
                finding.remediated_at = finding.detected_at + timedelta(days=extra["fix_after_days"])
                db.commit()

        for weeks, label, open_, crit, overdue, exposure, sla in [
            (12, "W-12", 14, 6, 9, 860.4, 18.2), (8, "W-8", 12, 5, 8, 742.9, 22.2), (4, "W-4", 9, 4, 6, 611.2, 28.6)]:
            db.add(RiskSnapshot(label=label, open_findings=open_, critical_findings=crit, overdue_findings=overdue,
                                total_exposure=exposure, sla_compliance=sla, created_at=NOW - timedelta(weeks=weeks)))
        db.commit()
        take_snapshot(db, label="Now")

        print(f"Seeded {len(assets)} assets, {len(vulns)} vulnerabilities, {db.query(Finding).count()} findings.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
