from pydantic_settings import BaseSettings
from pathlib import Path
import os
from dotenv import load_dotenv

# Load .env file from the backend directory
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

# Also try loading from current directory
load_dotenv()


class Settings(BaseSettings):
    google_safe_browsing_api_key: str | None = None
    openphish_feed_url: str = "https://openphish.com/feed.txt"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


settings = Settings()

# Debug: Print if API key is loaded (only show first few chars for security)
if settings.google_safe_browsing_api_key:
    print(f"[OK] Google Safe Browsing API key loaded: {settings.google_safe_browsing_api_key[:10]}...")
else:
    print("[WARNING] Google Safe Browsing API key not found. Set GOOGLE_SAFE_BROWSING_API_KEY in .env file")

