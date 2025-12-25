from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models import ScanHistory
from app.schemas import ScanHistoryCreate, ScanHistoryResponse

router = APIRouter(
    prefix="/history",
    tags=["history"]
)

@router.post("/", response_model=ScanHistoryResponse)
def create_scan_history(scan: ScanHistoryCreate, db: Session = Depends(get_db)):
    db_scan = ScanHistory(**scan.dict())
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan

@router.get("/{user_id}", response_model=List[ScanHistoryResponse])
def get_user_history(user_id: str, db: Session = Depends(get_db)):
    history = db.query(ScanHistory).filter(ScanHistory.user_id == user_id).order_by(ScanHistory.created_at.desc()).all()
    return history
