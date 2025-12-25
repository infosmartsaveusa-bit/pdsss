import httpx
from app.config import settings


GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


async def check_google_safe_browsing(url: str) -> dict:
    """
    Returns:
        {
          "flagged": bool,
          "details": dict
        }
    """
    api_key = settings.google_safe_browsing_api_key
    if not api_key:
        return {"flagged": False, "details": {}}

    payload = {
        "client": {
            "clientId": "phishing-scanner",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GSB_API_URL}?key={api_key}",
                json=payload,
                timeout=5
            )
            data = resp.json()
            flagged = "matches" in data
            return {"flagged": flagged, "details": data}

    except Exception:
        return {"flagged": False, "details": {}}


