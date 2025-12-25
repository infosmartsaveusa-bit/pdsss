"""
QR Code Scanner Service

This service handles QR code scanning with full functionality:
1. Decodes QR code images to extract URLs or text
2. Analyzes extracted URLs for phishing threats
3. Returns comprehensive scan results with risk scoring
"""

import numpy as np
import cv2
from pyzbar.pyzbar import decode as pyzbar_decode
from typing import Dict, Any, Optional

from app.services.url_scanner_service import scan_url_service


def decode_qr_image(image_bytes: bytes) -> Optional[str]:
    """
    Decodes a QR code from image bytes.
    
    Args:
        image_bytes: Raw image bytes (PNG, JPG, etc.)
        
    Returns:
        Decoded string from QR code, or None if no QR code found
    """
    try:
        # Convert bytes → numpy array → CV2 image
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            return None

        # Decode QR code
        decoded_objects = pyzbar_decode(img)
        if not decoded_objects:
            return None

        # Return first QR code found
        return decoded_objects[0].data.decode("utf-8")
    except Exception:
        return None


async def scan_qr_service(image_bytes: bytes) -> Dict[str, Any]:
    """
    Complete QR code scanning service with threat analysis.
    
    This function:
    1. Decodes the QR code image
    2. Identifies the content type (URL or text)
    3. If URL, performs full phishing analysis
    4. Returns comprehensive results
    
    Args:
        image_bytes: Raw image bytes containing QR code
        
    Returns:
        Dictionary with scan results:
        - decoded: The decoded content from QR code
        - type: Content type ('url', 'text', or 'invalid')
        - report: Full URL scan report (if type is 'url')
        - message: Status message
        - label: Risk verdict ('safe', 'suspicious', 'phishing')
        - score: Risk score 0-100
        - reasons: List of threat indicators
    """
    # Step 1: Decode QR code
    decoded = decode_qr_image(image_bytes)
    
    if not decoded:
        return {
            "decoded": None,
            "type": "invalid",
            "message": "No valid QR code found in image.",
            "label": "invalid",
            "score": 0,
            "reasons": ["Failed to decode QR code from image"]
        }
    
    # Step 2: Determine content type and analyze
    # Check if content is a URL
    if decoded.startswith(("http://", "https://", "ftp://")) or "." in decoded:
        # Normalize URL if needed
        url = decoded if decoded.startswith(("http://", "https://")) else f"http://{decoded}"
        
        try:
            # Step 3: Perform URL threat analysis
            url_result = await scan_url_service(url)
            
            return {
                "decoded": decoded,
                "type": "url",
                "message": "QR code contains a URL. Threat analysis completed.",
                "url": url_result.get("url", url),
                "label": url_result.get("label", "unknown"),
                "score": url_result.get("score", 0),
                "reasons": url_result.get("reasons", []),
                "domain_age": url_result.get("domain_age"),
                "ssl_certificate": url_result.get("ssl_certificate"),
                "report": url_result  # Full detailed report
            }
        except Exception as e:
            return {
                "decoded": decoded,
                "type": "url",
                "message": f"QR code contains URL but analysis failed: {str(e)}",
                "url": url,
                "label": "error",
                "score": 0,
                "reasons": [f"URL analysis error: {str(e)}"]
            }
    
    # Step 4: Handle non-URL content (plain text, contact info, etc.)
    else:
        # Analyze text for suspicious patterns
        suspicious_keywords = [
            "password", "login", "verify", "account", "urgent", 
            "suspended", "confirm", "security", "update", "click"
        ]
        
        text_lower = decoded.lower()
        found_keywords = [kw for kw in suspicious_keywords if kw in text_lower]
        
        # Basic risk assessment for text content
        if found_keywords:
            score = min(len(found_keywords) * 15, 50)  # Max 50 for text-only
            label = "suspicious" if score >= 30 else "safe"
            reasons = [f"Contains suspicious keyword: '{kw}'" for kw in found_keywords]
        else:
            score = 0
            label = "safe"
            reasons = ["No suspicious patterns detected in text content"]
        
        return {
            "decoded": decoded,
            "type": "text",
            "message": "QR code contains text data (not a URL).",
            "label": label,
            "score": score,
            "reasons": reasons
        }


async def scan_qr_from_file(file_bytes: bytes, filename: str = "") -> Dict[str, Any]:
    """
    Convenience wrapper for scanning QR codes from uploaded files.
    
    Args:
        file_bytes: Raw file bytes
        filename: Optional filename for logging
        
    Returns:
        Complete scan results from scan_qr_service
    """
    result = await scan_qr_service(file_bytes)
    
    # Add metadata
    result["filename"] = filename
    result["scan_type"] = "qr"
    
    return result


def get_qr_info(image_bytes: bytes) -> Dict[str, Any]:
    """
    Get basic information about a QR code without full threat analysis.
    Useful for quick validation.
    
    Args:
        image_bytes: Raw image bytes
        
    Returns:
        Basic QR code information
    """
    decoded = decode_qr_image(image_bytes)
    
    if not decoded:
        return {
            "valid": False,
            "decoded": None,
            "content_type": "invalid"
        }
    
    # Determine content type
    if decoded.startswith(("http://", "https://")):
        content_type = "url"
    elif "@" in decoded and "." in decoded:
        content_type = "email"
    elif decoded.startswith("tel:"):
        content_type = "phone"
    elif decoded.startswith("BEGIN:VCARD"):
        content_type = "vcard"
    else:
        content_type = "text"
    
    return {
        "valid": True,
        "decoded": decoded,
        "content_type": content_type,
        "length": len(decoded)
    }
