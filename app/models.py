from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from sqlalchemy.sql import func
from app.database import Base

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)  # UUID from frontend
    scan_type = Column(String)  # 'url', 'qr', 'email'
    target = Column(Text)  # The URL or content summary
    result = Column(JSON)  # Full scan result
    risk_score = Column(Integer)
    risk_label = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
