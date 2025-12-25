from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime

class ScanHistoryBase(BaseModel):
    user_id: str
    scan_type: str
    target: str
    result: Dict[str, Any]
    risk_score: int
    risk_label: str

class ScanHistoryCreate(ScanHistoryBase):
    pass

class ScanHistoryResponse(ScanHistoryBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True
