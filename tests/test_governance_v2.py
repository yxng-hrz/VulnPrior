import json
from datetime import datetime, timedelta, timezone

from app.config import settings
from app.models import Finding
from app.services.finding_service import rescore_all
from app.services.risk_engine import calculate_risk

NOW = datetime.now(timezone.utc)
BASE = dict(cvss=7.5, epss=0.4, kev=True, patch_available=True, asset_criticality=4, internet_exposed=False,
            contains_sensitive_data=False, environment="production")


def status(client, finding_id, **body):
    body.setdefault("actor", "secops@demo.local")
    return client.post(f"/api/v1/findings/{finding_id}/status", json=body)


def test_ransomware_use_increases_risk():
    assert calculate_risk(**BASE, ransomware_use=True).score > calculate_risk(**BASE).score
    assert "ransomware" in calculate_risk(**BASE, ransomware_use=True).explanation


def test_sla_deadline_is_anchored_on_detection(client, db, scenario):
    finding = db.get(Finding, scenario["findings"][1]["id"])
    finding.detected_at = NOW - timedelta(days=30)
    db.commit()
    rescore_all(db)
    db.refresh(finding)
    expected = finding.detected_at.replace(tzinfo=timezone.utc) + timedelta(hours=finding.sla_hours)
    assert abs((finding.sla_due_at.replace(tzinfo=timezone.utc) - expected).total_seconds()) < 1
    assert finding.overdue is True

    overdue = client.get("/api/v1/findings?overdue_only=true").json()
    assert [f["id"] for f in overdue] == [finding.id]
    assert overdue[0]["overdue"] is True
    summary = client.get("/api/v1/dashboard/summary").json()
    assert summary["overdue_findings"] == 1
    assert summary["sla_compliance_rate"] < 100


def test_lifecycle_guardrails(client, scenario):
    fid = scenario["findings"][2]["id"]
    assert status(client, fid, status="mitigated").status_code == 422          # no compensating control yet
    assert status(client, fid, status="false_positive", reason="short").status_code == 422
    assert status(client, fid, status="remediated").status_code == 200
    assert status(client, fid, status="in_progress").status_code == 409        # remediated -> in_progress not allowed
    assert status(client, fid, status="open").status_code == 200               # reopen is allowed

    client.patch(f"/api/v1/findings/{fid}", json={"compensating_control": "WAF virtual patch"})
    assert status(client, fid, status="mitigated").json()["status"] == "mitigated"


def test_risk_acceptance_rules(client, scenario):
    kev_finding, other = scenario["findings"][0]["id"], scenario["findings"][1]["id"]
    good = {"status": "risk_accepted", "reason": "Vendor patch breaks payment flow, waiting for hotfix",
            "approved_by": "cio@demo.local", "accepted_until": (NOW + timedelta(days=60)).isoformat()}

    assert status(client, other, **{**good, "approved_by": "secops@demo.local"}).status_code == 403  # four-eyes
    assert status(client, kev_finding, **good).status_code == 422                                   # KEV max 30 days
    too_long = {**good, "accepted_until": (NOW + timedelta(days=settings.acceptance_max_days + 5)).isoformat()}
    assert status(client, other, **too_long).status_code == 422

    accepted = status(client, other, **good).json()
    assert accepted["status"] == "risk_accepted"
    assert accepted["accepted_by"] == "cio@demo.local"


def test_expired_acceptance_returns_to_queue(client, db, scenario):
    fid = scenario["findings"][1]["id"]
    status(client, fid, status="risk_accepted", reason="Business freeze during peak season",
           approved_by="cio@demo.local", accepted_until=(NOW + timedelta(days=10)).isoformat())
    finding = db.get(Finding, fid)
    finding.accepted_until = NOW - timedelta(days=1)
    db.commit()
    client.get("/api/v1/dashboard/summary")
    db.refresh(finding)
    assert finding.status == "open"
    events = [e["event_type"] for e in client.get("/api/v1/audit").json()]
    assert "risk_acceptance_expired" in events


def test_mttr_and_sla_met_rate(client, scenario):
    fid = scenario["findings"][1]["id"]
    status(client, fid, status="in_progress")
    status(client, fid, status="remediated")
    summary = client.get("/api/v1/dashboard/summary").json()
    assert summary["remediated_findings"] == 1
    assert summary["remediated_within_sla_rate"] == 100.0
    assert summary["mttr_days"] is not None


def test_business_services_and_pareto(client, scenario):
    services = client.get("/api/v1/dashboard/business-services").json()
    assert services[0]["business_service"] == "Customer Portal"
    assert services[0]["known_exploited"] == 1
    impact = client.get("/api/v1/dashboard/remediation-impact?top=1").json()
    assert impact["finding_ids"] == [scenario["findings"][0]["id"]]
    assert 30 < impact["reduction_percent"] < 100


def test_remediation_plan_csv(client, scenario):
    plan = client.get("/api/v1/reports/remediation-plan").json()
    assert {group["owner"] for group in plan} == {"Digital", "IT"}
    csv_text = client.get("/api/v1/reports/remediation-plan?format=csv").text
    assert csv_text.splitlines()[0].startswith("owner,finding_id,cve_id")
    assert "CVE-2026-90001" in csv_text


def test_findings_csv_import_and_regression_reopen(client, scenario):
    fid = scenario["findings"][2]["id"]
    status(client, fid, status="remediated")
    csv_body = ("asset,cve_id,title,cvss,epss,kev,patch_available\n"
                "wiki,CVE-2026-90003,,,,,\n"
                "wiki,CVE-2026-95555,New scanner finding,7.2,0.2,false,true\n"
                "ghost-host,CVE-2026-90001,,,,,\n")
    result = client.post("/api/v1/imports/findings-csv", files={"file": ("scan.csv", csv_body, "text/csv")}).json()
    assert result["created"] == 1
    assert result["reopened"] == 1
    assert len(result["errors"]) == 1
    assert client.get(f"/api/v1/findings/{fid}").json()["status"] == "open"


def test_kev_file_enrichment_flags_ransomware_and_rescores(client, scenario):
    fid = scenario["findings"][1]["id"]
    before = client.get(f"/api/v1/findings/{fid}").json()["risk_score"]
    catalog = {"catalogVersion": "2026.11.16", "vulnerabilities": [
        {"cveID": "CVE-2026-90002", "knownRansomwareCampaignUse": "Known", "dateAdded": "2026-11-01", "dueDate": "2026-11-22"},
    ]}
    result = client.post("/api/v1/enrichment/kev-file",
                         files={"file": ("kev.json", json.dumps(catalog), "application/json")}).json()
    assert result["newly_flagged_kev"] == 1
    after = client.get(f"/api/v1/findings/{fid}").json()
    assert after["vulnerability"]["kev"] is True
    assert after["vulnerability"]["ransomware_use"] is True
    assert after["vulnerability"]["kev_due_date"] == "2026-11-22"
    assert after["risk_score"] > before


def test_epss_enrichment_offline_and_online(client, scenario, monkeypatch):
    offline = client.post("/api/v1/enrichment/epss", json={"scores": {"cve-2026-90003": 0.75}}).json()
    assert offline["vulnerabilities_updated"] == 1

    from app.routers import enrichment
    monkeypatch.setattr(enrichment, "fetch_epss", lambda cves: {"CVE-2026-90002": (0.97, 0.99)})
    online = client.post("/api/v1/enrichment/epss").json()
    assert online["vulnerabilities_updated"] == 1
    vuln = client.get(f"/api/v1/findings/{scenario['findings'][1]['id']}").json()["vulnerability"]
    assert vuln["epss"] == 0.97 and vuln["epss_percentile"] == 0.99


def test_executive_report_trend_methodology_and_audit(client, scenario):
    client.post("/api/v1/dashboard/snapshots?label=Before")
    status(client, scenario["findings"][0]["id"], status="remediated")
    client.post("/api/v1/dashboard/snapshots?label=After")
    trend = client.get("/api/v1/dashboard/trend").json()
    assert trend[0]["critical_findings"] > trend[-1]["critical_findings"]

    report = client.get("/api/v1/reports/executive").text
    assert "Business services most at risk" in report
    assert "Decisions requested" in report

    weights = client.get("/api/v1/dashboard/methodology").json()["weights"]
    assert weights["ransomware_use"] == settings.weight_ransomware
    assert client.get("/api/v1/audit/verify").json()["valid"] is True


def test_rbac(client, scenario, monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "a:admin,r:reviewer,u:auditor")
    fid = scenario["findings"][2]["id"]
    assert client.get("/api/v1/findings").status_code == 401
    assert client.get("/api/v1/findings", headers={"X-API-Key": "u"}).status_code == 200
    assert client.post(f"/api/v1/findings/{fid}/status", headers={"X-API-Key": "u"},
                       json={"status": "in_progress", "actor": "x"}).status_code == 403
    assert client.post(f"/api/v1/findings/{fid}/status", headers={"X-API-Key": "r"},
                       json={"status": "in_progress", "actor": "x"}).status_code == 200
    assert client.post("/api/v1/findings/rescore", headers={"X-API-Key": "r"}).status_code == 403
    assert client.post("/api/v1/findings/rescore", headers={"X-API-Key": "a"}).status_code == 200
