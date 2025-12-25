import httpx
from app.config import settings


class OpenPhish:
    def __init__(self):
        self.urls = set()

    async def load_feed(self):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(settings.openphish_feed_url, timeout=10)
                lines = resp.text.splitlines()
                self.urls = set(line.strip() for line in lines if line.strip())
        except Exception:
            self.urls = set()

    def is_phishing(self, url: str) -> bool:
        return url in self.urls


openphish = OpenPhish()


async def check_openphish(url: str) -> dict:
    """
    Check if URL is in OpenPhish feed.
    
    Returns:
        {
          "flagged": bool,
          "details": dict
        }
    """
    flagged = openphish.is_phishing(url)
    
    return {
        "flagged": flagged,
        "details": {
            "source": "OpenPhish",
            "match_type": "feed" if flagged else None
        }
    }

