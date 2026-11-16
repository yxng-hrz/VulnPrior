import os
from pathlib import Path

TEST_DB = Path(__file__).parent / "test_vulnprior.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["API_KEYS"] = ""

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def scenario(client):
    """Three findings: KEV on an exposed portal, HIGH on a finance ERP, LOW on an internal wiki."""
    assets = [
        {"name": "customer-portal-prod", "owner": "Digital", "criticality": 5, "internet_exposed": True,
         "contains_sensitive_data": True, "business_service": "Customer Portal"},
        {"name": "erp-prod", "owner": "IT", "criticality": 5, "internet_exposed": False,
         "contains_sensitive_data": True, "business_service": "Finance"},
        {"name": "wiki", "owner": "IT", "criticality": 2, "environment": "production", "business_service": "Collaboration"},
    ]
    vulns = [
        {"cve_id": "CVE-2026-90001", "title": "Synthetic RCE", "cvss": 9.8, "epss": 0.9, "kev": True, "patch_available": True},
        {"cve_id": "CVE-2026-90002", "title": "Synthetic auth bypass", "cvss": 8.8, "epss": 0.6, "patch_available": True},
        {"cve_id": "CVE-2026-90003", "title": "Synthetic info leak", "cvss": 5.3, "epss": 0.02},
    ]
    asset_ids = [client.post("/api/v1/assets", json=a).json()["id"] for a in assets]
    vuln_ids = [client.post("/api/v1/vulnerabilities", json=v).json()["id"] for v in vulns]
    findings = [client.post("/api/v1/findings", json={"asset_id": a, "vulnerability_id": v}).json()
                for a, v in zip(asset_ids, vuln_ids)]
    return {"asset_ids": asset_ids, "vuln_ids": vuln_ids, "findings": findings}
