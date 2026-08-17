from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import Base, SessionLocal, engine
from app.models import Asset, Finding, Vulnerability
from app.services.finding_service import score_finding


ASSETS = [
    {
        "name": "customer-portal-prod",
        "owner": "Digital",
        "environment": "production",
        "criticality": 5,
        "internet_exposed": True,
        "contains_sensitive_data": True,
        "business_service": "Customer Portal",
    },
    {
        "name": "finance-api-prod",
        "owner": "Finance IT",
        "environment": "production",
        "criticality": 5,
        "internet_exposed": False,
        "contains_sensitive_data": True,
        "business_service": "Finance",
    },
    {
        "name": "internal-wiki",
        "owner": "IT",
        "environment": "production",
        "criticality": 2,
        "internet_exposed": False,
        "contains_sensitive_data": False,
        "business_service": "Collaboration",
    },
    {
        "name": "dev-ci-runner",
        "owner": "Platform",
        "environment": "development",
        "criticality": 3,
        "internet_exposed": True,
        "contains_sensitive_data": False,
        "business_service": "Software Delivery",
    },
]


VULNS = [
    {
        "cve_id": "CVE-2026-10001",
        "title": "Demo remote code execution",
        "description": "Synthetic demo vulnerability used for portfolio testing.",
        "cvss": 9.8,
        "epss": 0.91,
        "kev": True,
        "patch_available": True,
    },
    {
        "cve_id": "CVE-2026-10002",
        "title": "Demo authentication bypass",
        "description": "Synthetic demo vulnerability used for portfolio testing.",
        "cvss": 8.8,
        "epss": 0.62,
        "kev": False,
        "patch_available": True,
    },
    {
        "cve_id": "CVE-2026-10003",
        "title": "Demo information disclosure",
        "description": "Synthetic demo vulnerability used for portfolio testing.",
        "cvss": 6.5,
        "epss": 0.08,
        "kev": False,
        "patch_available": False,
    },
    {
        "cve_id": "CVE-2026-10004",
        "title": "Demo privilege escalation",
        "description": "Synthetic demo vulnerability used for portfolio testing.",
        "cvss": 7.8,
        "epss": 0.35,
        "kev": True,
        "patch_available": False,
    },
]


def seed():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        db.query(Finding).delete()
        db.query(Vulnerability).delete()
        db.query(Asset).delete()
        db.commit()

        assets = [Asset(**item) for item in ASSETS]
        vulnerabilities = [Vulnerability(**item) for item in VULNS]
        db.add_all(assets + vulnerabilities)
        db.flush()

        pairs = [
            (assets[0], vulnerabilities[0]),
            (assets[0], vulnerabilities[2]),
            (assets[1], vulnerabilities[1]),
            (assets[1], vulnerabilities[3]),
            (assets[2], vulnerabilities[2]),
            (assets[3], vulnerabilities[0]),
        ]

        findings = []
        for asset, vulnerability in pairs:
            finding = Finding(asset=asset, vulnerability=vulnerability)
            score_finding(finding)
            findings.append(finding)

        db.add_all(findings)
        db.commit()
        print(f"Seeded {len(assets)} assets, {len(vulnerabilities)} vulnerabilities, {len(findings)} findings.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
