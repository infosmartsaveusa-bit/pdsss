from fastapi import APIRouter
from pydantic import BaseModel
from app.services.url_scanner_service import scan_url_service
from app.services.redirect_chain_service import get_redirect_chain
from app.services.screenshot_service import capture_screenshot
import base64

router = APIRouter()

class URLRequestModel(BaseModel):
    url: str

class URLReportResponse(BaseModel):
    scan_result: dict
    redirect_chain: dict
    screenshot: str

@router.post("/api/url/report", response_model=URLReportResponse)
async def generate_url_report(payload: URLRequestModel):
    """
    Generate a complete report for a URL including:
    - Phishing/suspicious scan result
    - Redirect chain analysis
    - Screenshot capture
    """
    # Get the standard scan result
    scan_result = await scan_url_service(payload.url)
    
    # Get redirect chain
    redirect_chain = await get_redirect_chain(payload.url)
    
    # Capture screenshot
    try:
        screenshot_bytes = await capture_screenshot(payload.url)
        screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')
        screenshot_data = f"data:image/png;base64,{screenshot_base64}"
    except Exception as e:
        screenshot_data = f"{{\"error\": \"Could not capture screenshot: {str(e)}\"}}"
    
    return {
        "scan_result": scan_result,
        "redirect_chain": redirect_chain,
        "screenshot": screenshot_data
    }