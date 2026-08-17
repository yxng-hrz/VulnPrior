from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import Asset, Finding, Vulnerability
from app.services.risk_engine import calculate_risk


def score_finding(finding: Finding) -> Finding:
    result = calculate_risk(
        cvss=finding.vulnerability.cvss,
        epss=finding.vulnerability.epss,
        kev=finding.vulnerability.kev,
        patch_available=finding.vulnerability.patch_available,
        asset_criticality=finding.asset.criticality,
        internet_exposed=finding.asset.internet_exposed,
        contains_sensitive_data=finding.asset.contains_sensitive_data,
        environment=finding.asset.environment,
        compensating_control=bool((finding.compensating_control or "").strip()),
    )

    finding.risk_score = result.score
    finding.risk_level = result.level
    finding.sla_hours = result.sla_hours
    finding.decision = result.decision
    finding.explanation = result.explanation
    finding.due_date = (
        datetime.now(timezone.utc) + timedelta(hours=result.sla_hours)
    ).isoformat()
    return finding


def rescore_all(db: Session) -> int:
    findings = db.query(Finding).all()
    for finding in findings:
        score_finding(finding)
    db.commit()
    return len(findings)


def create_finding(
    db: Session,
    *,
    asset_id: int,
    vulnerability_id: int,
    risk_owner: str = "",
    notes: str = "",
) -> Finding:
    asset = db.get(Asset, asset_id)
    vulnerability = db.get(Vulnerability, vulnerability_id)
    if asset is None:
        raise ValueError("Asset not found")
    if vulnerability is None:
        raise ValueError("Vulnerability not found")

    finding = Finding(
        asset=asset,
        vulnerability=vulnerability,
        risk_owner=risk_owner,
        notes=notes,
    )
    score_finding(finding)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding
