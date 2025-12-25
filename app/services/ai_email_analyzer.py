"""
AI-style Email Phishing Analyzer (heuristic, no external LLM required)

This module inspects email subject/body/sender for phishing patterns such as:
- urgency language
- fake login / account verification phrases
- banking / payment fraud attempts
- credential harvesting patterns
- suspicious attachment references
- fake sender signatures
- lookalike / brand-abuse domains mentioned in text

It outputs:
    {
        "ai_text_score": int 0-100,
        "ai_text_label": "safe" | "suspicious" | "phishing",
        "indicators": [ "short description", ... ]
    }
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

import tldextract


URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "immediate action",
    "asap",
    "act now",
    "right away",
    "within 24 hours",
    "limited time",
    "last chance",
    "expires soon",
    "final notice",
    "account suspended",
    "account locked",
    "verify your account",
]

FAKE_LOGIN_PHRASES = [
    "login to your account",
    "log in to your account",
    "sign in to your account",
    "verify your login",
    "confirm your account",
    "update your account",
    "secure your account",
    "password reset required",
]

BANK_FRAUD_PHRASES = [
    "unusual activity",
    "unauthorized transaction",
    "fraudulent activity",
    "suspicious transaction",
    "bank account",
    "credit card",
    "debit card",
    "wire transfer",
]

CREDENTIAL_HARVESTING_PATTERNS = [
    "enter your password",
    "confirm your password",
    "provide your credentials",
    "update your login details",
    "validate your identity",
    "confirm your identity",
]

ATTACHMENT_KEYWORDS = [
    ".zip",
    ".rar",
    ".7z",
    ".exe",
    ".scr",
    ".js",
    "open the attached file",
    "see attachment",
    "see the attached document",
]

FAKE_SIGNATURE_PHRASES = [
    "security team",
    "account security",
    "billing department",
    "compliance team",
    "verification team",
]

BRAND_KEYWORDS = [
    "paypal",
    "apple",
    "amazon",
    "microsoft",
    "google",
    "gmail",
    "outlook",
    "bank",
    "netflix",
    "facebook",
    "instagram",
]


def _contains_any(text: str, phrases: List[str]) -> List[str]:
    text_lower = text.lower()
    found = []
    for phrase in phrases:
        if phrase.lower() in text_lower:
            found.append(phrase)
    return found


def _extract_domains_from_text(text: str) -> List[str]:
    """
    Extract domain-like tokens from arbitrary text (e.g., in signatures).
    """
    candidates = set()
    # Very simple URL / domain-like pattern
    for match in re.findall(r"\b(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b", text):
        candidates.add(match.lower())
    return list(candidates)


def _detect_lookalike_domains(text: str) -> List[str]:
    domains = _extract_domains_from_text(text)
    lookalikes = []
    for dom in domains:
        parsed = tldextract.extract(dom)
        base = parsed.domain.lower()
        for brand in BRAND_KEYWORDS:
            if brand in base and base != brand:
                lookalikes.append(dom)
                break
    return lookalikes


def analyze_email_text(
    subject: str = "",
    body: str = "",
    sender: str = "",
) -> Dict[str, object]:
    """
    Heuristic "AI-style" analysis for phishing content in email text.
    """
    score = 0
    indicators: List[str] = []

    combined = f"{subject}\n{body}".lower()

    # 1. Urgency
    found_urgency = _contains_any(combined, URGENCY_KEYWORDS)
    if found_urgency:
        score += 20
        indicators.append(
            f"Urgency / pressure language detected: {', '.join(found_urgency[:5])}"
        )

    # 2. Fake login / account verification
    found_login = _contains_any(combined, FAKE_LOGIN_PHRASES)
    if found_login:
        score += 20
        indicators.append(
            f"Account login / verification prompts detected: {', '.join(found_login[:5])}"
        )

    # 3. Banking / payment fraud phrases
    found_bank = _contains_any(combined, BANK_FRAUD_PHRASES)
    if found_bank:
        score += 15
        indicators.append(
            f"Banking / payment fraud language detected: {', '.join(found_bank[:5])}"
        )

    # 4. Credential harvesting
    found_creds = _contains_any(combined, CREDENTIAL_HARVESTING_PATTERNS)
    if found_creds:
        score += 15
        indicators.append(
            f"Credential harvesting language detected: {', '.join(found_creds[:5])}"
        )

    # 5. Suspicious attachment mentions
    found_attach = _contains_any(combined, ATTACHMENT_KEYWORDS)
    if found_attach:
        score += 10
        indicators.append(
            f"Suspicious attachment references detected: {', '.join(found_attach[:5])}"
        )

    # 6. Generic / fake signatures
    if _contains_any(combined, FAKE_SIGNATURE_PHRASES):
        score += 5
        indicators.append("Generic security/compliance team signature language detected.")

    # 7. Lookalike domains in text/signature
    lookalikes = _detect_lookalike_domains(combined)
    if lookalikes:
        score += 10
        indicators.append(
            f"Lookalike or brand-abuse domains mentioned: {', '.join(lookalikes[:3])}"
        )

    # 8. Sender/display-name anomalies (very lightweight)
    if sender:
        if re.search(r"[0-9]{6,}", sender):
            score += 5
            indicators.append("Sender address/display name contains long numeric patterns.")

    # Clamp score
    score = max(0, min(score, 100))

    if score >= 60:
        label = "phishing"
    elif score >= 30:
        label = "suspicious"
    else:
        label = "safe"

    if not indicators:
        indicators.append("No strong phishing patterns detected in email text.")

    return {
        "ai_text_score": score,
        "ai_text_label": label,
        "indicators": indicators,
    }



