"""
Integration example showing how to incorporate the AI phishing analyzer 
into the existing url_scanner_service.

This is not meant to be run directly, but shows where and how to integrate 
the new functionality.
"""

# In url_scanner_service.py, you would add the import:
# from app.services.ai_phish_analyzer import analyze_page

# Then in the scan_url_service function, you could add:

async def scan_url_service_with_ai_integration(url: str) -> dict:
    """
    Example showing integration of AI phishing analysis into URL scanning.
    This is an illustration of how to modify the existing scan_url_service function.
    """
    
    # After getting the HTML content (around line 150 in the original)
    html_content = None
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            resp = await client.get(url)
            html_content = resp.text[:200_000]
    except Exception:
        html_content = None

    # AI-Powered Phishing Analysis (NEW)
    try:
        ai_analysis = analyze_page(url, html_content)
    except Exception as exc:
        ai_analysis = {
            "ai_score": 0,
            "indicators": [f"AI analysis failed: {str(exc)}"],
        }

    # Incorporate AI score into final scoring (around line 170 in original)
    ai_score = int(ai_analysis.get("ai_score", 0))
    ai_indicators = ai_analysis.get("indicators", [])
    
    # Weight the AI score (e.g., contribute 30% to final score)
    ai_contribution = int(ai_score * 0.3)
    final_score = min(result["score"] + ai_contribution, 100)
    final_label = _label_from_score(final_score)

    # Update result dictionary to include AI analysis
    result["ai_analysis"] = {
        "ai_score": ai_score,
        "indicators": ai_indicators,
        "contribution_to_final_score": ai_contribution
    }
    result["final_score"] = final_score
    result["final_label"] = final_label

    return result