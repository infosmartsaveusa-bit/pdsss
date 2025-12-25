from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import List

import tldextract

BRAND_LIST = [
    "google",
    "paypal",
    "amazon",
    "icloud",
    "microsoft",
    "apple",
    "facebook",
    "instagram",
    "bank",
    "hdfc",
    "sbi",
    "icici",
]

LOGIN_KEYWORDS = [
    "login",
    "sign in",
    "password",
    "enter your credentials",
    "verify your account",
]

BANKING_KEYWORDS = [
    "bank",
    "account statement",
    "verify card",
    "update kyc",
    "account restricted",
]

FORM_PATTERNS = [
    r'<input[^>]+type=["\']password',
    r'<input[^>]+name=["\']otp',
    r'<input[^>]+name=["\']pin',
]

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "biz", "xyz", "zip", "top"}


def _normalize_domain(url: str) -> tuple[str, str, str]:
    extracted = tldextract.extract(url)
    suffix = extracted.suffix.lower() if extracted.suffix else ""
    domain_label = ".".join(
        part for part in (extracted.domain, extracted.suffix) if part
    ).lower()
    core_domain = extracted.domain.lower() if extracted.domain else domain_label
    return core_domain, suffix, domain_label or url.lower()


def _html_contains_keywords(html_lower: str, keywords: List[str]) -> bool:
    return any(keyword in html_lower for keyword in keywords)


def _detect_lookalike(core_domain: str) -> bool:
    for brand in BRAND_LIST:
        similarity = SequenceMatcher(a=core_domain, b=brand).ratio()
        if similarity >= 0.75 and core_domain != brand:
            return True
    return False


def _detect_suspicious_forms(html: str) -> bool:
    for pattern in FORM_PATTERNS:
        if re.search(pattern, html, flags=re.IGNORECASE):
            return True
    return False


def analyze_with_ai(url: str, html: str | None) -> dict:
    """
    Lightweight heuristic analyzer that scores phishing risk signals (0-100).
    """
    score = 0
    details: List[str] = []

    core_domain, suffix, display_domain = _normalize_domain(url)

    if core_domain and _detect_lookalike(core_domain):
        score += 30
        details.append(f"Detected lookalike domain: {display_domain}")

    if suffix in SUSPICIOUS_TLDS:
        score += 10
        details.append(f"Suspicious TLD detected: .{suffix}")

    if html:
        lower_html = html.lower()

        if _html_contains_keywords(lower_html, LOGIN_KEYWORDS):
            score += 25
            details.append("Login page detected")

        if _html_contains_keywords(lower_html, BANKING_KEYWORDS):
            score += 25
            details.append("Banking flow indicators detected")

        if _detect_suspicious_forms(html):
            score += 20
            details.append("Suspicious form fields detected")

    ai_score = min(score, 100)
    return {
        "ai_score": ai_score,
        "ai_details": details,
    }

