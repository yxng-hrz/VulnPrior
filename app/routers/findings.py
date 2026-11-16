from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models import Finding
from app.schemas import FindingCreate, FindingRead, FindingUpdate, StatusChange
from app.security import ADMIN, ANY_ROLE, REVIEWER, Principal
from app.services.audit import log_event
from app.services.finding_service import change_status, create_finding as service_create_finding
from app.services.finding_service import expire_acceptances, is_overdue, rescore_all, score_finding

router = APIRouter(prefix="/findings", tags=["findings & remediation"], dependencies=[Depends(ANY_ROLE)])


def _query(db: Session):
    return db.query(Finding).options(joinedload(Finding.asset), joinedload(Finding.vulnerability))


def _get(db: Session, finding_id: int) -> Finding:
    finding = _query(db).filter(Finding.id == finding_id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("", response_model=list[FindingRead])
def list_findings(
    level: str | None = Query(default=None),
    status: str | None = Query(default=None),
    kev_only: bool = Query(default=False),
    overdue_only: bool = Query(default=False),
    owner: str | None = Query(default=None),
    business_service: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    expire_acceptances(db)
    query = _query(db)
    if level:
        query = query.filter(Finding.risk_level == level.upper())
    if status:
        query = query.filter(Finding.status == status.lower())
    if kev_only:
        query = query.filter(Finding.vulnerability.has(kev=True))
    if business_service:
        query = query.filter(Finding.asset.has(business_service=business_service))
    findings = query.order_by(Finding.risk_score.desc()).all()
    if owner:
        findings = [f for f in findings if (f.risk_owner or f.asset.owner) == owner]
    if overdue_only:
        findings = [f for f in findings if is_overdue(f)]
    return findings[:limit]


@router.get("/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    return _get(db, finding_id)


@router.post("", response_model=FindingRead, status_code=201)
def create_finding(payload: FindingCreate, db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    try:
        return service_create_finding(db, **payload.model_dump(), actor=principal.name)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Finding already exists for this asset and vulnerability") from exc


@router.patch("/{finding_id}", response_model=FindingRead)
def update_finding(finding_id: int, payload: FindingUpdate, db: Session = Depends(get_db), principal: Principal = Depends(REVIEWER)):
    finding = _get(db, finding_id)
    updates = payload.model_dump(exclude_unset=True)
    for key, value in updates.items():
        setattr(finding, key, value)
    score_finding(finding)
    log_event(db, "finding_updated", actor=principal.name, entity_type="finding", entity_id=str(finding.id),
              details=", ".join(sorted(updates)))
    db.commit()
    db.refresh(finding)
    return finding


@router.post("/{finding_id}/status", response_model=FindingRead, dependencies=[Depends(REVIEWER)])
def set_status(finding_id: int, payload: StatusChange, db: Session = Depends(get_db)):
    """Remediation workflow with guardrails: allowed transitions, four-eyes risk acceptance, time-bound exceptions."""
    finding = _get(db, finding_id)
    return change_status(db, finding, status=payload.status, actor=payload.actor, reason=payload.reason,
                         approved_by=payload.approved_by, accepted_until=payload.accepted_until)


@router.post("/rescore", status_code=200, dependencies=[Depends(ADMIN)])
def rescore_findings(db: Session = Depends(get_db)):
    return {"rescored": rescore_all(db)}
