from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Vulnerability
from app.schemas import VulnerabilityCreate, VulnerabilityRead
from app.security import ADMIN, ANY_ROLE

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"], dependencies=[Depends(ANY_ROLE)])


@router.get("", response_model=list[VulnerabilityRead])
def list_vulnerabilities(db: Session = Depends(get_db)):
    return db.query(Vulnerability).order_by(Vulnerability.cvss.desc()).all()


@router.post("", response_model=VulnerabilityRead, status_code=201, dependencies=[Depends(ADMIN)])
def create_vulnerability(payload: VulnerabilityCreate, db: Session = Depends(get_db)):
    if db.query(Vulnerability).filter(Vulnerability.cve_id == payload.cve_id).first():
        raise HTTPException(status_code=409, detail="CVE already exists")
    vulnerability = Vulnerability(**payload.model_dump())
    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)
    return vulnerability


@router.get("/{vulnerability_id}", response_model=VulnerabilityRead)
def get_vulnerability(vulnerability_id: int, db: Session = Depends(get_db)):
    vulnerability = db.get(Vulnerability, vulnerability_id)
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vulnerability
