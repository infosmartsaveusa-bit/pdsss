import asyncio
import base64
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from app.services.url_scanner_service import scan_url_service
from app.services.openphish_service import openphish

app = FastAPI(
    title="Phishing Detection API",
    version="0.1.0",
    description="URL, QR, and Email phishing detection service",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # allow all origins during development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def load_feeds():
    await openphish.load_feed()


class URLScanRequest(BaseModel):
    url: str


class URLScanResponse(BaseModel):
    url: str
    label: str
    score: int
    reasons: list[str]


class URLRequestModel(BaseModel):
    url: str


@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.post("/scan/url", response_model=URLScanResponse)
async def scan_url(payload: URLScanRequest):
    result = await scan_url_service(payload.url)
    return result


@app.post("/scan/qr")
async def scan_qr(file: UploadFile = File(...)):
    """
    Accepts image upload (PNG/JPG), decodes QR, and performs threat analysis.
    Uses the comprehensive QR scanner service.
    """
    from app.services.qr_scanner_service import scan_qr_from_file
    
    image_bytes = await file.read()
    result = await scan_qr_from_file(image_bytes, filename=file.filename)
    
    return result


@app.post("/url/screenshot")
async def analyze_url_screenshot(request: URLRequestModel):
    """
    Analyze URL and return screenshot and redirect chain.
    """
    try:
        # Import the screenshot service here to avoid issues during startup
        from app.services.screenshot_service import get_redirect_chain, capture_screenshot
        
        # Get redirect chain
        redirect_chain = await get_redirect_chain(request.url)
        
        # Capture screenshot
        screenshot_bytes = await capture_screenshot(request.url)
        screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')
        
        return {
            "redirect_chain": redirect_chain,
            "screenshot": screenshot_base64
        }
    except Exception as e:
        return {
            "redirect_chain": [],
            "screenshot": None,
            "error": str(e)
        }


# Import routers
from app.routers.url_scanner import router as url_scanner_router
from app.routers.history import router as history_router
from app.routers.email_scanner import router as email_scanner_router
from app.database import engine, Base

# Create database tables
Base.metadata.create_all(bind=engine)

# Include the routers
app.include_router(url_scanner_router)
app.include_router(history_router)
app.include_router(email_scanner_router)