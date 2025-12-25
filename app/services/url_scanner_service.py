from datetime import datetime, timezone

import httpx
import tldextract
import validators

# Updated import to use the new AI phishing analyzer
from app.services.ai_phish_analyzer import analyze_page
from app.services.gsb_service import check_google_safe_browsing
from app.services.openphish_service import openphish
from app.services.domain_utils import get_domain_age, get_ssl_certificate


def _label_from_score(score: int) -> str:
    if score >= 60:
        return "phishing"
    if score >= 30:
        return "suspicious"
    return "safe"


async def scan_url_service(url: str) -> dict:
    reasons = []
    score = 0

    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Validate format
    if not validators.url(url):
        return {
            "url": url,
            "label": "invalid",
            "score": 100,
            "reasons": ["URL format is invalid"]
        }

    # Extract domain
    extracted = tldextract.extract(url)
    main_domain = f"{extracted.domain}.{extracted.suffix}"

    # Get domain age and SSL certificate info
    domain_age = get_domain_age(main_domain)
    ssl_info = get_ssl_certificate(main_domain)

    # Domain age check
    if isinstance(domain_age.get("age_days"), int) and domain_age["age_days"] < 30:
        score += 15
        reasons.append("Domain is newly registered (< 30 days)")

    # SSL certificate check
    # Only flag SSL as "invalid" for specific issues:
    # - Certificate is expired
    # - Self-signed
    # - Hostname mismatch
    # - No SSL on HTTPS
    ssl_issues = []
    if ssl_info["valid"] is False:
        ssl_issues.append("Invalid or missing SSL certificate")
    
    # Apply penalty only for actual SSL issues, not fetching errors
    if ssl_issues:
        score += 15
        reasons.extend(ssl_issues)
    else:
        # If SSL expires soon, treat as additional risk
        try:
            if ssl_info["valid_to"]:
                # Parse the date string from the certificate
                import ssl
                import datetime as dt
                valid_to = dt.datetime.strptime(ssl_info["valid_to"], "%b %d %H:%M:%S %Y %Z")
                valid_to = valid_to.replace(tzinfo=dt.timezone.utc)
                days_left = (valid_to - dt.datetime.now(dt.timezone.utc)).days
                if days_left < 15:
                    score += 10
                    reasons.append("SSL certificate expires very soon")
        except Exception:
            # Parsing issue shouldn't break scan; just skip "expires soon" check
            pass

    # ----------------------------
    # 1. Google Safe Browsing check
    # ----------------------------
    gsb = await check_google_safe_browsing(url)
    gsb_score = 60 if gsb["flagged"] else 0
    if gsb["flagged"]:
        score += 60
        reasons.append("Flagged by Google Safe Browsing")

    # ----------------------------
    # 2. OpenPhish blocklist
    # ----------------------------
    if openphish.is_phishing(url):
        score += 60
        reasons.append("Found in OpenPhish phishing feed")

    # ----------------------------
    # 3. Heuristic Rules
    # ----------------------------
    # Very long URL
    if len(url) > 120:
        score += 10
        reasons.append("URL is unusually long")

    # Suspicious TLDs
    bad_tlds = {"tk", "ml", "xyz", "zip", "top", "click"}
    if extracted.suffix in bad_tlds:
        score += 15
        reasons.append(f"Suspicious TLD: .{extracted.suffix}")

    # Too many special characters
    if url.count("-") > 3 or url.count("@") > 0:
        score += 10
        reasons.append("Contains many special characters")

    # Fake login pages
    suspicious_keywords = ["login", "verify", "update", "secure", "account"]
    if any(word in url.lower() for word in suspicious_keywords):
        score += 10
        reasons.append("Contains phishing-related keywords")

    label = _label_from_score(score)

    # After all rule-based & AI checks add:
    return {
        "url": url,
        "label": label,
        "score": min(score, 100),
        "reasons": reasons,
        "domain_age": domain_age,
        "ssl_certificate": ssl_info,
    }