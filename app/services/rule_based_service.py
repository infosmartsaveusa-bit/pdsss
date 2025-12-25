import re
from difflib import SequenceMatcher
from urllib.parse import urlparse, parse_qs

import tldextract


# Suspicious patterns
SUSPICIOUS_PATTERNS = [
    (r'bit\.ly|tinyurl|goo\.gl|t\.co|short\.link', "URL shortener detected"),
    (r'login[_-]?.*\.[a-z]{2,}|sign[_-]?in.*\.[a-z]{2,}', "Suspicious login page"),
    (r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', "IP address in URL"),
    (r'[a-z0-9-]+\.(tk|ml|ga|cf|gq)', "Suspicious TLD detected"),
    (r'[a-z0-9]+\.(com|net|org)\.(tk|ml|ga|cf)', "Double domain suspicious pattern"),
    (r'secure[_-]?.*[_-]?verify|account[_-]?verify|confirm[_-]?.*', "Suspicious verification URL"),
    (r'[a-z0-9-]+-[a-z0-9-]+-[a-z0-9-]+\.(com|net|org)', "Highly suspicious domain pattern"),
]

# Suspicious keywords
SUSPICIOUS_KEYWORDS = [
    ("login", 2),
    ("verify", 3),
    ("account", 2),
    ("secure", 2),
    ("update", 2),
    ("suspended", 5),
    ("locked", 4),
    ("urgent", 3),
    ("immediately", 4),
    ("action required", 5),
]

# Trusted domains (can be expanded)
TRUSTED_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "chase.com",
]

# Suspicious query parameters
SUSPICIOUS_QUERY_PARAMS = [
    "redirect", "return", "next", "goto", "url", "link", "target"
]


def _strong_phishing_rules(url: str):
    """
    Enhanced scoring rules ensuring high-risk phishing URLs exceed threshold.
    """
    parsed_url = urlparse(url)
    tld_parts = tldextract.extract(parsed_url.netloc)
    domain = tld_parts.domain or parsed_url.netloc
    suffix = tld_parts.suffix
    full_domain = (
        f"{tld_parts.domain}.{tld_parts.suffix}".lower()
        if tld_parts.domain and tld_parts.suffix
        else (tld_parts.domain or parsed_url.netloc).lower()
    )
    path = (parsed_url.path or "").lower()

    score = 0
    reasons = []

    phishing_terms = [
        "secure",
        "security",
        "verify",
        "login",
        "update",
        "account",
        "billing",
        "support",
        "center",
    ]
    if any(word in full_domain for word in phishing_terms):
        score += 20
        reasons.append("Suspicious keyword found in domain")

    known_brands = ["paypal", "google", "facebook", "amazon", "microsoft"]
    for brand in known_brands:
        ratio = SequenceMatcher(None, (domain or "").lower(), brand).ratio()
        if 0.55 < ratio < 0.95:
            score += 35
            reasons.append(f"Lookalike domain detected (similar to {brand})")
            break

    bad_paths = ["verify", "login", "auth", "update", "security"]
    if any(p in path for p in bad_paths):
        score += 20
        reasons.append("Suspicious path detected")

    return score, reasons


def check_rule_based(url: str) -> dict:
    """
    Rule-based phishing detection.
    
    Returns:
        {
          "flagged": bool,
          "details": dict,
          "score": int,  # Suspiciousness score (0-100)
          "reasons": list[str]
        }
    """
    reasons = []
    score = 0
    details = {}
    
    parsed = urlparse(url.lower())
    domain = parsed.netloc
    path = parsed.path
    query_params = parse_qs(parsed.query)
    
    # Check trusted domains (negative score adjustment)
    is_trusted = any(trusted in domain for trusted in TRUSTED_DOMAINS)
    
    # Pattern matching
    for pattern, reason in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            reasons.append(reason)
            score += 5
    
    # Keyword checking (in path and domain)
    for keyword, keyword_score in SUSPICIOUS_KEYWORDS:
        if keyword in path or keyword in domain:
            reasons.append(f"Suspicious keyword detected: '{keyword}'")
            score += keyword_score
    
    # Check for suspicious query parameters
    for param in SUSPICIOUS_QUERY_PARAMS:
        if param in query_params:
            reasons.append(f"Suspicious query parameter: '{param}'")
            score += 3
    
    # Check domain length (very long domains are suspicious)
    if len(domain) > 50:
        reasons.append("Unusually long domain name")
        score += 4
    
    # Check for hyphen count (many hyphens are suspicious)
    hyphen_count = domain.count("-")
    if hyphen_count > 3:
        reasons.append(f"Too many hyphens in domain ({hyphen_count})")
        score += 3
    
    # Check for mixed case (phishing domains often use mixed case)
    if any(c.isupper() for c in parsed.netloc):
        reasons.append("Mixed case in domain (possible spoofing)")
        score += 2
    
    # HTTPS check
    if parsed.scheme != "https":
        reasons.append("Not using HTTPS")
        score += 5
    
    # Port check (non-standard ports are suspicious for common services)
    if parsed.port and parsed.port not in [80, 443, 8080]:
        reasons.append(f"Non-standard port: {parsed.port}")
        score += 3
    
    # Strong phishing heuristics (ensures clearly malicious URLs exceed threshold)
    strong_score, strong_reasons = _strong_phishing_rules(url)
    if strong_score:
        score += strong_score
        reasons.extend(strong_reasons)

    # Trusted domain check (reduce score if trusted)
    if is_trusted and score > 0:
        score = max(0, score - 10)
        details["trusted_domain"] = True
    
    # Normalize score to 0-100
    score = min(100, score)
    
    # Flag if score exceeds threshold
    flagged = score >= 15
    
    details["suspiciousness_score"] = score
    
    return {
        "flagged": flagged,
        "details": details,
        "score": score,
        "reasons": reasons
    }


