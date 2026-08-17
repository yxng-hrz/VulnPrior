from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models import Finding
from app.schemas import FindingCreate, FindingRead, FindingUpdate
from app.services.finding_service import create_finding as service_create_finding
from app.services.finding_service import rescore_all, score_finding

router = APIRouter(prefix="/findings", tags=["findings"])


def _query(db: Session):
    return db.query(Finding).options(
        joinedload(Finding.asset),
        joinedload(Finding.vulnerability),
    )


@router.get("", response_model=list[FindingRead])
def list_findings(
    level: str | None = Query(default=None),
    status: str | None = Query(default=None),
    kev_only: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = _query(db)
    if level:
        query = query.filter(Finding.risk_level == level.upper())
    if status:
        query = query.filter(Finding.status == status.lower())
    if kev_only:
        query = query.filter(Finding.vulnerability.has(kev=True))
    return query.order_by(Finding.risk_score.desc()).limit(limit).all()


@router.post("", response_model=FindingRead, status_code=201)
def create_finding(payload: FindingCreate, db: Session = Depends(get_db)):
    try:
        return service_create_finding(db, **payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Finding already exists for this asset and vulnerability",
        ) from exc


@router.patch("/{finding_id}", response_model=FindingRead)
def update_finding(
    finding_id: int,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
):
    finding = _query(db).filter(Finding.id == finding_id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    updates = payload.model_dump(exclude_unset=True)
    for key, value in updates.items():
        setattr(finding, key, value)

    score_finding(finding)
    db.commit()
    db.refresh(finding)
    return finding


@router.post("/rescore", status_code=200)
def rescore_findings(db: Session = Depends(get_db)):
    count = rescore_all(db)
    return {"rescored": count}
