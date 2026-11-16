from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset
from app.schemas import AssetCreate, AssetRead
from app.security import ADMIN, ANY_ROLE

router = APIRouter(prefix="/assets", tags=["assets"], dependencies=[Depends(ANY_ROLE)])


@router.get("", response_model=list[AssetRead])
def list_assets(db: Session = Depends(get_db)):
    return db.query(Asset).order_by(Asset.name.asc()).all()


@router.post("", response_model=AssetRead, status_code=201, dependencies=[Depends(ADMIN)])
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    if db.query(Asset).filter(Asset.name == payload.name).first():
        raise HTTPException(status_code=409, detail="Asset already exists")
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/{asset_id}", response_model=AssetRead)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.delete("/{asset_id}", status_code=204, dependencies=[Depends(ADMIN)])
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
