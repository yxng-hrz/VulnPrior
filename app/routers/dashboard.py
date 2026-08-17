from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Finding, Vulnerability
from app.schemas import DashboardSummary, RiskPreviewRequest, RiskPreviewResponse
from app.services.risk_engine import calculate_risk

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def summary(db: Session = Depends(get_db)):
    total = db.query(func.count(Finding.id)).scalar() or 0
    open_count = (
        db.query(func.count(Finding.id))
        .filter(Finding.status == "open")
        .scalar()
        or 0
    )
    critical = (
        db.query(func.count(Finding.id))
        .filter(Finding.risk_level == "CRITICAL")
        .scalar()
        or 0
    )
    high = (
        db.query(func.count(Finding.id))
        .filter(Finding.risk_level == "HIGH")
        .scalar()
        or 0
    )
    kev = (
        db.query(func.count(Finding.id))
        .join(Vulnerability)
        .filter(Vulnerability.kev.is_(True))
        .scalar()
        or 0
    )
    internet = (
        db.query(func.count(Finding.id))
        .join(Finding.asset)
        .filter_by(internet_exposed=True)
        .scalar()
        or 0
    )
    avg = db.query(func.avg(Finding.risk_score)).scalar() or 0.0
    assets = db.query(func.count(func.distinct(Finding.asset_id))).scalar() or 0

    return DashboardSummary(
        total_findings=total,
        open_findings=open_count,
        critical_findings=critical,
        high_findings=high,
        kev_findings=kev,
        internet_exposed_findings=internet,
        average_risk_score=round(float(avg), 1),
        assets_affected=assets,
    )


@router.post("/risk-preview", response_model=RiskPreviewResponse)
def risk_preview(payload: RiskPreviewRequest):
    result = calculate_risk(**payload.model_dump())
    return RiskPreviewResponse(
        score=result.score,
        level=result.level,
        sla_hours=result.sla_hours,
        decision=result.decision,
        explanation=result.explanation,
        factors=result.factors,
    )
