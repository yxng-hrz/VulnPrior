import csv
import io

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Vulnerability

router = APIRouter(prefix="/imports", tags=["imports"])


def _bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


@router.post("/assets-csv")
async def import_assets_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    content = (await file.read()).decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    required = {"name", "criticality", "internet_exposed"}
    if not reader.fieldnames or not required.issubset(reader.fieldnames):
        raise HTTPException(
            status_code=400,
            detail=f"CSV requires columns: {sorted(required)}",
        )

    created = 0
    skipped = 0
    for row in reader:
        name = row["name"].strip()
        if db.query(Asset).filter(Asset.name == name).first():
            skipped += 1
            continue
        asset = Asset(
            name=name,
            owner=row.get("owner", "Unknown") or "Unknown",
            environment=row.get("environment", "production") or "production",
            criticality=int(row.get("criticality", 3)),
            internet_exposed=_bool(row.get("internet_exposed", "false")),
            contains_sensitive_data=_bool(row.get("contains_sensitive_data", "false")),
            business_service=row.get("business_service", "General") or "General",
        )
        db.add(asset)
        created += 1
    db.commit()
    return {"created": created, "skipped": skipped}


@router.post("/vulnerabilities-csv")
async def import_vulnerabilities_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    content = (await file.read()).decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    required = {"cve_id", "title", "cvss", "epss", "kev"}
    if not reader.fieldnames or not required.issubset(reader.fieldnames):
        raise HTTPException(
            status_code=400,
            detail=f"CSV requires columns: {sorted(required)}",
        )

    created = 0
    skipped = 0
    for row in reader:
        cve_id = row["cve_id"].strip().upper()
        if db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first():
            skipped += 1
            continue
        vulnerability = Vulnerability(
            cve_id=cve_id,
            title=row["title"].strip(),
            description=row.get("description", ""),
            cvss=float(row.get("cvss", 0)),
            epss=float(row.get("epss", 0)),
            kev=_bool(row.get("kev", "false")),
            patch_available=_bool(row.get("patch_available", "false")),
            published_at=row.get("published_at") or None,
        )
        db.add(vulnerability)
        created += 1
    db.commit()
    return {"created": created, "skipped": skipped}
