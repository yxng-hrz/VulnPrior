from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Finding, Vulnerability
from app.schemas import DashboardSummary, RiskPreviewRequest, RiskPreviewResponse, SnapshotRead
from app.security import ADMIN, ANY_ROLE, Principal
from app.services.audit import log_event
from app.services.finding_service import (
    EXPOSED_STATUSES, business_service_exposure, expire_acceptances, governance_metrics, remediation_impact,
)
from app.services.report_service import take_snapshot, trend
from app.services.risk_engine import calculate_risk, methodology

router = APIRouter(prefix="/dashboard", tags=["dashboard & governance"], dependencies=[Depends(ANY_ROLE)])


@router.get("/summary", response_model=DashboardSummary)
def summary(db: Session = Depends(get_db)):
    expire_acceptances(db)
    exposed = db.query(Finding).filter(Finding.status.in_(EXPOSED_STATUSES))

    def count(query) -> int:
        return query.count()

    metrics = governance_metrics(db)
    avg = exposed.with_entities(func.avg(Finding.risk_score)).scalar() or 0.0
    return DashboardSummary(
        total_findings=db.query(Finding).count(),
        open_findings=metrics["exposed_findings"],
        critical_findings=count(exposed.filter(Finding.risk_level == "CRITICAL")),
        high_findings=count(exposed.filter(Finding.risk_level == "HIGH")),
        kev_findings=count(exposed.join(Vulnerability).filter(Vulnerability.kev.is_(True))),
        ransomware_findings=count(exposed.join(Vulnerability).filter(Vulnerability.ransomware_use.is_(True))),
        internet_exposed_findings=count(exposed.join(Asset).filter(Asset.internet_exposed.is_(True))),
        average_risk_score=round(float(avg), 1),
        total_exposure=metrics["total_exposure"],
        assets_affected=exposed.with_entities(func.count(func.distinct(Finding.asset_id))).scalar() or 0,
        overdue_findings=metrics["overdue_findings"],
        overdue_critical=metrics["overdue_critical"],
        sla_compliance_rate=metrics["sla_compliance_rate"],
        remediated_findings=metrics["remediated_findings"],
        mttr_days=metrics["mttr_days"],
        remediated_within_sla_rate=metrics["remediated_within_sla_rate"],
        risk_accepted_findings=db.query(Finding).filter(Finding.status == "risk_accepted").count(),
        acceptances_expiring_14d=metrics["acceptances_expiring_14d"],
    )


@router.get("/business-services")
def business_services(db: Session = Depends(get_db)):
    """Exposure aggregated by business service — the language a COMEX understands."""
    return business_service_exposure(db)


@router.get("/remediation-impact")
def get_remediation_impact(top: int = Query(default=5, ge=1, le=100), db: Session = Depends(get_db)):
    """Pareto analysis: share of total exposure removed by fixing the N riskiest findings."""
    return remediation_impact(db, top)


@router.get("/methodology")
def get_methodology():
    return methodology()


@router.post("/risk-preview", response_model=RiskPreviewResponse)
def risk_preview(payload: RiskPreviewRequest):
    result = calculate_risk(**payload.model_dump())
    return RiskPreviewResponse(score=result.score, level=result.level, sla_hours=result.sla_hours,
                               decision=result.decision, explanation=result.explanation, factors=result.factors)


@router.post("/snapshots", response_model=SnapshotRead, status_code=201)
def snapshot(label: str = "", db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    snap = take_snapshot(db, label=label)
    log_event(db, "risk_snapshot", actor=principal.name, entity_type="snapshot", entity_id=str(snap.id),
              details=f"label={label}; exposure={snap.total_exposure}")
    db.commit()
    return snap


@router.get("/trend", response_model=list[SnapshotRead])
def get_trend(limit: int = Query(default=12, ge=1, le=100), db: Session = Depends(get_db)):
    return trend(db, limit)
