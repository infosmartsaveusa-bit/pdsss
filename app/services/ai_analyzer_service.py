# backend/app/services/ai_analyzer_service.py

import re
import difflib
import math
import json
import asyncio
from typing import Optional, Dict, Any, List
import tldextract

# Optional: import httpx for LLM call if you want to call Cursor/OpenAI
# import httpx
# from app.config import settings

BRAND_KEYWORDS = [
    "google", "gmail", "paypal", "apple", "amazon", "bank", "win", "microsoft",
    "facebook", "fb", "linkedin", "dropbox", "stripe"
]

PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "password", "banking",
    "confirm", "signin", "reset", "urgent", "limited", "verify-account"
]

SUSPICIOUS_TLDS = {"tk", "ml", "xyz", "zip", "top", "click", "cf"}

LLM_SYSTEM_PROMPT = (
    "You are a concise security assistant. Always output valid JSON only, no commentary."
)


def simple_normalize_domain(domain: str) -> str:
    return domain.lower().strip().lstrip("www.")


def fuzzy_contains_brand(domain: str, brand: str) -> float:
    """
    Return similarity ratio between domain and brand. Higher => more likely lookalike.
    """
    return difflib.SequenceMatcher(a=domain, b=brand).ratio()


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


async def call_llm(system_prompt: str, user_prompt: str) -> Optional[Dict[str, Any]]:
    """
    Optional: call your LLM here (Cursor/OpenAI). If you don't have a key
    or don't want to call, simply return None to use heuristic result.
    Replace this function with your actual SDK call.
    """
    # Example placeholder - returns None to skip LLM by default
    return None


def heuristic_analysis(url: str, html: Optional[str] = None) -> Dict[str, Any]:
    """
    Run deterministic heuristics and produce a score (0..100) and reasons.
    """
    reasons: List[str] = []
    score = 0

    parsed = tldextract.extract(url)
    domain = f"{parsed.domain}.{parsed.suffix}" if parsed.suffix else parsed.domain
    norm_domain = simple_normalize_domain(domain)

    # 1) suspicious TLD
    if parsed.suffix in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"Suspicious TLD: .{parsed.suffix}")

    # 2) suspicious keywords in hostname/path
    lower = url.lower()
    if any(k in lower for k in PHISHING_KEYWORDS):
        score += 12
        reasons.append("Contains phishing-related keywords")

    # 3) too long / many hyphens
    if len(url) > 120:
        score += 8
        reasons.append("URL unusually long")
    if url.count("-") > 3:
        score += 5
        reasons.append("Contains many hyphens")

    # 4) repeated brand-like tokens (e.g. paypal.com.security-...)
    for brand in BRAND_KEYWORDS:
        if brand in norm_domain and norm_domain != brand:
            # domain contains brand but is not exactly brand -> suspicious
            score += 12
            reasons.append(f"Domain contains brand-like token: {brand}")
            break

    # 5) lookalike detection (fuzzy compare domain tokens to brand)
    # split domain tokens
    tokens = re.split(r"[\W_]+", parsed.domain.lower())
    for token in tokens:
        for brand in BRAND_KEYWORDS:
            ratio = fuzzy_contains_brand(token, brand)
            if 0.7 <= ratio < 1.0 and token != brand:
                score += 10
                reasons.append(f"Domain token '{token}' looks like brand '{brand}' (similarity {ratio:.2f})")
                break

    # 6) presence of login forms (if html passed)
    if html:
        try:
            # naive detection for <input type="password"> or forms pointing to external hosts
            if re.search(r'<input[^>]+type=["\']?password', html, flags=re.I):
                score += 20
                reasons.append("Contains password input (login form)")

            # forms with action pointing to different domain
            forms = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', html, flags=re.I)
            for action in forms:
                # if action exists and domain of action differs from original -> suspicious
                aex = tldextract.extract(action)
                if aex.domain and aex.domain != parsed.domain:
                    score += 8
                    reasons.append("Form action posts to an external domain")
                    break
        except Exception:
            # keep resilient
            pass

    # 7) squeeze the score into 0-100
    score = min(max(score, 0), 100)

    # baseline minor safety: if score is 0, say "no indicators found"
    if score == 0:
        reasons.append("No obvious phishing indicators found by heuristics")

    return {
        "source": "heuristic",
        "score": score,
        "reasons": reasons,
        "domain": domain
    }


async def analyze_url(url: str, html: Optional[str] = None, screenshot_text: Optional[str] = None) -> Dict[str, Any]:
    """
    Main entrypoint. Returns:
    {
      "score": int,
      "label": "safe"|"suspicious"|"phishing",
      "reasons": [..],
      "meta": {...}
    }
    """
    heur = heuristic_analysis(url, html=html)
    score = heur["score"]
    reasons = heur["reasons"]

    # Try LLM to refine response (optional)
    # build prompt (structured) with heuristics results & ask for JSON output
    notes_text = (
        "If heuristics already show clear malicious markers (score >= 60), don't reduce risk."
    )
    user_prompt = (
        "System prompt\n\n"
        f"{LLM_SYSTEM_PROMPT}\n\n"
        "User prompt\n\n"
        "Analyze the following phishing heuristics and raw page signals. Output JSON with:\n"
        "{\n"
        '  "risk_score": int,\n'
        '  "label": "safe"|"suspicious"|"phishing",\n'
        '  "reasons": ["short reason 1", "short reason 2"]\n'
        "}\n\n"
        f"Input:\n\nURL: {url}\n\nHeuristics: {json.dumps(heur)}\n\n"
        f"HTML snippet available: {bool(html)}\n\n"
        f"Screenshot text available: {bool(screenshot_text)}\n\n"
        f"Additional notes: {notes_text}\n\n"
        "Important: return only JSON as described."
    )
    llm_result = await call_llm(LLM_SYSTEM_PROMPT, user_prompt)

    if llm_result:
        # Expecting: {"risk_score": int, "label": str, "reasons": [..]}
        try:
            risk_score = int(llm_result.get("risk_score", score))
            risk_score = min(max(risk_score, 0), 100)
            label = llm_result.get("label", None)
            reasons_llm = llm_result.get("reasons", [])
            if not label:
                # derive label from risk
                if risk_score >= 60:
                    label = "phishing"
                elif risk_score >= 30:
                    label = "suspicious"
                else:
                    label = "safe"

            return {
                "score": risk_score,
                "label": label,
                "reasons": list(dict.fromkeys(reasons + reasons_llm)),  # unique
                "meta": {"heuristic": heur, "llm_raw": llm_result}
            }
        except Exception:
            # fallback to heuristics
            pass

    # no LLM or LLM failed -> use heuristics only
    label = "safe" if score < 30 else ("suspicious" if score < 60 else "phishing")
    return {
        "score": score,
        "label": label,
        "reasons": reasons,
        "meta": {"heuristic": heur}
    }

