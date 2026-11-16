"""Finding scoring, remediation lifecycle and governance metrics."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.models import Asset, Finding, Vulnerability
from app.services.audit import log_event
from app.services.risk_engine import calculate_risk

EXPOSED_STATUSES = {"open", "in_progress", "mitigated"}
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "open": {"in_progress", "mitigated", "remediated", "risk_accepted", "false_positive"},
    "in_progress": {"open", "mitigated", "remediated", "risk_accepted", "false_positive"},
    "mitigated": {"open", "in_progress", "remediated", "risk_accepted"},
    "remediated": {"open"},                       # regression / re-detection only
    "risk_accepted": {"open", "in_progress", "remediated"},
    "false_positive": {"open"},
}


def as_aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def is_overdue(finding: Finding, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    due = as_aware(finding.sla_due_at)
    return bool(due and finding.status in EXPOSED_STATUSES and now > due)


# --- Scoring --------------------------------------------------------------------------------

def score_finding(finding: Finding) -> Finding:
    result = calculate_risk(
        cvss=finding.vulnerability.cvss,
        epss=finding.vulnerability.epss,
        kev=finding.vulnerability.kev,
        ransomware_use=finding.vulnerability.ransomware_use,
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
    # The deadline is anchored on detection: rescoring never silently extends an SLA.
    detected = as_aware(finding.detected_at) or datetime.now(timezone.utc)
    finding.sla_due_at = detected + timedelta(hours=result.sla_hours)
    return finding


def rescore_all(db: Session) -> int:
    findings = db.query(Finding).all()
    for finding in findings:
        score_finding(finding)
    db.commit()
    return len(findings)


def create_finding(db: Session, *, asset_id: int, vulnerability_id: int, risk_owner: str = "", notes: str = "",
                   ticket_ref: str = "", actor: str = "api") -> Finding:
    asset = db.get(Asset, asset_id)
    vulnerability = db.get(Vulnerability, vulnerability_id)
    if asset is None:
        raise ValueError("Asset not found")
    if vulnerability is None:
        raise ValueError("Vulnerability not found")
    finding = Finding(asset=asset, vulnerability=vulnerability, risk_owner=risk_owner, notes=notes,
                      ticket_ref=ticket_ref, detected_at=datetime.now(timezone.utc))
    score_finding(finding)
    db.add(finding)
    db.flush()
    log_event(db, "finding_created", actor=actor, entity_type="finding", entity_id=str(finding.id),
              details=f"{vulnerability.cve_id} on {asset.name}; {finding.risk_level} {finding.risk_score}")
    db.commit()
    db.refresh(finding)
    return finding


# --- Lifecycle ------------------------------------------------------------------------------

def change_status(db: Session, finding: Finding, *, status: str, actor: str, reason: str = "",
                  approved_by: str = "", accepted_until: datetime | None = None) -> Finding:
    current = finding.status
    if status == current:
        raise HTTPException(status_code=409, detail=f"Finding is already {status}")
    if status not in ALLOWED_TRANSITIONS.get(current, set()):
        raise HTTPException(status_code=409, detail=f"Transition {current} -> {status} is not allowed")

    now = datetime.now(timezone.utc)
    if status == "mitigated" and not finding.compensating_control.strip():
        raise HTTPException(status_code=422, detail="Document the compensating control before marking as mitigated")
    if status == "false_positive" and len(reason.strip()) < 10:
        raise HTTPException(status_code=422, detail="A false positive requires a documented technical reason")

    if status == "risk_accepted":
        if len(reason.strip()) < 10 or not approved_by.strip() or accepted_until is None:
            raise HTTPException(status_code=422, detail="Risk acceptance requires reason, approver and expiry date")
        if approved_by.strip().lower() == actor.strip().lower():
            raise HTTPException(status_code=403, detail="Four-eyes principle: the approver must differ from the requester")
        until = as_aware(accepted_until)
        max_days = settings.kev_acceptance_max_days if finding.vulnerability.kev else settings.acceptance_max_days
        if until <= now:
            raise HTTPException(status_code=422, detail="Acceptance expiry must be in the future")
        if until > now + timedelta(days=max_days):
            raise HTTPException(status_code=422, detail=f"Acceptance cannot exceed {max_days} days for this finding"
                                + (" (known exploited vulnerability)" if finding.vulnerability.kev else ""))
        finding.accepted_by, finding.accepted_until, finding.acceptance_justification = approved_by, until, reason
    elif current == "risk_accepted":
        finding.accepted_by, finding.accepted_until, finding.acceptance_justification = "", None, ""

    if status == "remediated":
        finding.remediated_at = now
    if status == "open" and current in {"remediated", "false_positive"}:
        finding.reopened_count += 1
        finding.remediated_at = None

    finding.status = status
    log_event(db, "finding_status_changed", actor=actor, entity_type="finding", entity_id=str(finding.id),
              details=f"{current} -> {status}" + (f"; approved_by={approved_by}; until={as_aware(accepted_until).date()}" if status == "risk_accepted" else "")
              + (f"; reason={reason}" if reason else ""))
    db.commit()
    db.refresh(finding)
    return finding


def expire_acceptances(db: Session) -> int:
    """Expired risk acceptances automatically return to the remediation queue."""
    now = datetime.now(timezone.utc)
    expired = [f for f in db.query(Finding).filter(Finding.status == "risk_accepted").all()
               if f.accepted_until is None or as_aware(f.accepted_until) < now]
    for finding in expired:
        finding.status = "open"
        log_event(db, "risk_acceptance_expired", actor="system", entity_type="finding", entity_id=str(finding.id),
                  details=f"accepted_by={finding.accepted_by}; back to remediation queue")
        finding.accepted_by, finding.accepted_until = "", None
    if expired:
        db.commit()
    return len(expired)


# --- Governance metrics ---------------------------------------------------------------------

def _all(db: Session) -> list[Finding]:
    return db.query(Finding).options(joinedload(Finding.asset), joinedload(Finding.vulnerability)).all()


def governance_metrics(db: Session) -> dict:
    now = datetime.now(timezone.utc)
    findings = _all(db)
    exposed = [f for f in findings if f.status in EXPOSED_STATUSES]
    overdue = [f for f in exposed if is_overdue(f, now)]
    remediated = [f for f in findings if f.status == "remediated" and f.remediated_at]
    durations = [(as_aware(f.remediated_at) - as_aware(f.detected_at)).total_seconds() / 86400 for f in remediated]
    in_sla = [f for f in remediated if as_aware(f.remediated_at) <= as_aware(f.sla_due_at)]
    soon = now + timedelta(days=14)
    return {
        "exposed_findings": len(exposed),
        "overdue_findings": len(overdue),
        "overdue_critical": sum(1 for f in overdue if f.risk_level == "CRITICAL"),
        "total_exposure": round(sum(f.risk_score for f in exposed), 1),
        "sla_compliance_rate": round(100 * (len(exposed) - len(overdue)) / len(exposed), 1) if exposed else 100.0,
        "remediated_findings": len(remediated),
        "mttr_days": round(sum(durations) / len(durations), 1) if durations else None,
        "remediated_within_sla_rate": round(100 * len(in_sla) / len(remediated), 1) if remediated else None,
        "acceptances_expiring_14d": sum(1 for f in findings if f.status == "risk_accepted"
                                        and f.accepted_until and as_aware(f.accepted_until) <= soon),
    }


def business_service_exposure(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    groups: dict[str, dict] = defaultdict(lambda: {"exposure": 0.0, "findings": 0, "critical": 0, "overdue": 0,
                                                    "known_exploited": 0, "owners": set(), "assets": set()})
    for f in _all(db):
        if f.status not in EXPOSED_STATUSES:
            continue
        g = groups[f.asset.business_service]
        g["exposure"] += f.risk_score
        g["findings"] += 1
        g["critical"] += f.risk_level == "CRITICAL"
        g["overdue"] += is_overdue(f, now)
        g["known_exploited"] += f.vulnerability.kev
        g["owners"].add(f.risk_owner or f.asset.owner)
        g["assets"].add(f.asset.name)
    rows = [{"business_service": name, **{k: v for k, v in g.items() if k not in {"owners", "assets"}},
             "exposure": round(g["exposure"], 1), "owners": sorted(g["owners"]), "assets": sorted(g["assets"])}
            for name, g in groups.items()]
    return sorted(rows, key=lambda r: -r["exposure"])


def remediation_impact(db: Session, top: int = 5) -> dict:
    """Pareto view: how much exposure disappears if the N riskiest findings are fixed."""
    exposed = sorted([f for f in _all(db) if f.status in EXPOSED_STATUSES], key=lambda f: -f.risk_score)
    total = sum(f.risk_score for f in exposed)
    selected = exposed[:top]
    removed = sum(f.risk_score for f in selected)
    curve, running = [], 0.0
    for index, f in enumerate(exposed, start=1):
        running += f.risk_score
        curve.append({"fixed": index, "cumulative_reduction_percent": round(100 * running / total, 1) if total else 0.0})
    return {
        "top": top,
        "finding_ids": [f.id for f in selected],
        "total_exposure": round(total, 1),
        "exposure_removed": round(removed, 1),
        "reduction_percent": round(100 * removed / total, 1) if total else 0.0,
        "curve": curve,
    }


def remediation_plan(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in sorted([f for f in _all(db) if f.status in EXPOSED_STATUSES], key=lambda f: as_aware(f.sla_due_at)):
        groups[f.risk_owner or f.asset.owner].append({
            "finding_id": f.id, "cve_id": f.vulnerability.cve_id, "asset": f.asset.name,
            "business_service": f.asset.business_service, "risk_level": f.risk_level, "risk_score": f.risk_score,
            "decision": f.decision, "sla_due_at": as_aware(f.sla_due_at).isoformat(), "overdue": is_overdue(f, now),
            "ticket_ref": f.ticket_ref,
        })
    return sorted(
        [{"owner": owner, "open_items": len(items), "overdue_items": sum(i["overdue"] for i in items), "items": items}
         for owner, items in groups.items()],
        key=lambda g: (-g["overdue_items"], -g["open_items"], g["owner"]),
    )


# --- Scanner import -------------------------------------------------------------------------

def _bool(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def import_findings_rows(db: Session, rows: list[dict], actor: str) -> dict:
    """Ingest a scanner export (asset, cve_id, …): creates CVEs and findings, re-opens regressions."""
    created, reopened, skipped, errors = 0, 0, 0, []
    assets = {a.name: a for a in db.query(Asset).all()}
    for index, row in enumerate(rows, start=2):
        asset = assets.get((row.get("asset") or "").strip())
        cve_id = (row.get("cve_id") or "").strip().upper()
        if asset is None or not cve_id:
            errors.append(f"row {index}: unknown asset or missing cve_id")
            continue
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
        if vuln is None:
            if not (row.get("title") or "").strip() or not (row.get("cvss") or "").strip():
                errors.append(f"row {index}: new CVE {cve_id} needs at least title and cvss")
                continue
            vuln = Vulnerability(cve_id=cve_id, title=row["title"].strip(), cvss=float(row["cvss"]),
                                 epss=float(row.get("epss") or 0), kev=_bool(row.get("kev", "false")),
                                 patch_available=_bool(row.get("patch_available", "false")))
            db.add(vuln)
            db.flush()
        finding = db.query(Finding).filter(Finding.asset_id == asset.id, Finding.vulnerability_id == vuln.id).first()
        if finding is None:
            finding = Finding(asset=asset, vulnerability=vuln, detected_at=datetime.now(timezone.utc))
            score_finding(finding)
            db.add(finding)
            created += 1
        elif finding.status in {"remediated", "false_positive"}:
            previous = finding.status
            finding.status = "open"
            finding.reopened_count += 1
            finding.remediated_at = None
            finding.detected_at = datetime.now(timezone.utc)
            score_finding(finding)
            log_event(db, "finding_reopened", actor=actor, entity_type="finding", entity_id=str(finding.id),
                      details=f"re-detected by scanner (was {previous})")
            reopened += 1
        else:
            skipped += 1
    log_event(db, "scanner_import", actor=actor, details=f"created={created}; reopened={reopened}; skipped={skipped}; errors={len(errors)}")
    db.commit()
    return {"created": created, "reopened": reopened, "skipped": skipped, "errors": errors}
