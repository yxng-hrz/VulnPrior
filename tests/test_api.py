def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_end_to_end_finding_creation(client):
    asset = client.post(
        "/api/v1/assets",
        json={
            "name": "public-api",
            "owner": "Platform",
            "environment": "production",
            "criticality": 5,
            "internet_exposed": True,
            "contains_sensitive_data": True,
            "business_service": "API",
        },
    )
    assert asset.status_code == 201

    vuln = client.post(
        "/api/v1/vulnerabilities",
        json={
            "cve_id": "CVE-2026-99999",
            "title": "Synthetic critical issue",
            "cvss": 9.8,
            "epss": 0.9,
            "kev": True,
            "patch_available": True,
        },
    )
    assert vuln.status_code == 201

    finding = client.post(
        "/api/v1/findings",
        json={
            "asset_id": asset.json()["id"],
            "vulnerability_id": vuln.json()["id"],
            "risk_owner": "CISO",
        },
    )
    assert finding.status_code == 201
    body = finding.json()
    assert body["risk_level"] == "CRITICAL"
    assert body["sla_hours"] == 24

    summary = client.get("/api/v1/dashboard/summary")
    assert summary.status_code == 200
    assert summary.json()["total_findings"] == 1
    assert summary.json()["critical_findings"] == 1


def test_risk_preview(client):
    response = client.post(
        "/api/v1/dashboard/risk-preview",
        json={
            "cvss": 7.5,
            "epss": 0.4,
            "kev": False,
            "patch_available": True,
            "asset_criticality": 4,
            "internet_exposed": True,
            "contains_sensitive_data": False,
            "environment": "production",
            "compensating_control": False,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert 0 <= body["score"] <= 100
    assert body["level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
