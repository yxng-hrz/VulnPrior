import json

import httpx
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Vulnerability
from app.schemas import EpssRequest
from app.security import ADMIN, Principal
from app.services.threat_intel import apply_epss, apply_kev, fetch_epss, fetch_kev_catalog

router = APIRouter(prefix="/enrichment", tags=["threat intelligence"])


@router.post("/epss")
def enrich_epss(payload: EpssRequest | None = None, db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    """Refresh EPSS scores from FIRST (or from an offline payload) and re-score every finding."""
    if payload and payload.scores:
        scores = {cve.upper(): (float(value), 0.0) for cve, value in payload.scores.items()}
    else:
        cves = [v.cve_id for v in db.query(Vulnerability).all()]
        try:
            scores = fetch_epss(cves) if cves else {}
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"EPSS feed unavailable: {exc}") from exc
    return apply_epss(db, scores, actor=principal.name)


@router.post("/kev")
def enrich_kev(db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    """Pull the CISA Known Exploited Vulnerabilities catalogue, flag matches (incl. ransomware use) and re-score."""
    try:
        catalog = fetch_kev_catalog()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"KEV feed unavailable: {exc}. Use /enrichment/kev-file instead.") from exc
    return apply_kev(db, catalog, actor=principal.name)


@router.post("/kev-file")
async def enrich_kev_file(file: UploadFile = File(...), db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    """Offline mode: upload a KEV JSON file downloaded from cisa.gov."""
    try:
        catalog = json.loads((await file.read()).decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="File must be the CISA KEV JSON catalogue") from exc
    if "vulnerabilities" not in catalog:
        raise HTTPException(status_code=400, detail="Missing 'vulnerabilities' key: not a KEV catalogue")
    return apply_kev(db, catalog, actor=principal.name)
