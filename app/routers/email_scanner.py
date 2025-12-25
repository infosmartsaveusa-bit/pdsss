# app/routers/email_scanner.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from app.services.email_scanner_service import scan_email_service

router = APIRouter(prefix="/scan", tags=["email"])


class EmailScanRequest(BaseModel):
    subject: Optional[str] = ""
    sender: Optional[str] = ""  # "from" field
    body: Optional[str] = ""
    links: Optional[List[str]] = None
    attachments: Optional[List[Dict[str, Any]]] = None
    raw_headers: Optional[str] = None


@router.post("/email")
async def scan_email(request: EmailScanRequest):
    """
    Scan an email for phishing indicators.
    Returns detailed analysis including URL reports, sender domain info, and risk score.
    """
    try:
        result = await scan_email_service(
            subject=request.subject or "",
            sender=request.sender or "",
            body=request.body or "",
            links=request.links,
            attachments=request.attachments,
            raw_headers=request.raw_headers,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email scan failed: {str(e)}")
