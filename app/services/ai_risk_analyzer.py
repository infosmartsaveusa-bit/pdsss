"""
AI-Powered Phishing Risk Analyzer

This module provides heuristic-based AI analysis for detecting phishing attempts
by analyzing HTML content and domain characteristics.
"""

import re
import httpx
from typing import List, Dict
from urllib.parse import urlparse, urljoin
import tldextract


# Known popular brands for domain comparison
POPULAR_BRANDS = [
    "google", "apple", "paypal", "microsoft", "amazon", 
    "instagram", "facebook", "netflix", "twitter", "linkedin",
    "ebay", "yahoo", "outlook", "hotmail", "gmail", "bankofamerica",
    "chase", "wellsfargo", "citibank", "amazonaws"
]

# Suspicious keywords in HTML content
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", 
    "password", "bank", "wallet", "credentials"
]

# Urgent/suspicious phrases
URGENT_PHRASES = [
    "verify your account", "suspended", "urgent", "click here",
    "verify now", "account suspended", "immediate action required",
    "verify immediately", "your account will be closed", "security alert",
    "unauthorized access", "verify identity", "confirm your identity"
]

# Suspicious TLDs
SUSPICIOUS_TLDS = {".zip", ".xyz", ".top", ".loan", ".click", ".tk", ".ml", ".cf"}

# Homoglyph character mappings (common lookalike characters)
HOMOGLYPHS = {
    '0': 'o',
    '1': 'i',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '6': 'g',
    '7': 't',
    '8': 'b',
    '9': 'g',
    'o': '0',
    'i': '1',
    'e': '3',
    'a': '4',
    's': '5',
    'g': '6',
    't': '7',
    'b': '8'
}


def normalize_domain(domain: str) -> str:
    """
    Normalize domain by replacing homoglyphs with common characters.
    This helps detect lookalike domains.
    """
    normalized = domain.lower()
    for char, replacement in HOMOGLYPHS.items():
        normalized = normalized.replace(char, replacement)
    return normalized


def detect_lookalike_domain(domain: str) -> bool:
    """
    Detect if a domain is a lookalike of a popular brand.
    """
    domain_lower = domain.lower()
    normalized_domain = normalize_domain(domain_lower)
    
    # Remove TLD for comparison
    domain_without_tld = domain_lower.split('.')[0] if '.' in domain_lower else domain_lower
    normalized_without_tld = normalized_domain.split('.')[0] if '.' in normalized_domain else normalized_domain
    
    for brand in POPULAR_BRANDS:
        brand_lower = brand.lower()
        
        # Direct substring match
        if brand_lower in domain_without_tld and domain_without_tld != brand_lower:
            return True
        
        # Check for homoglyph variations
        if len(domain_without_tld) == len(brand_lower):
            # Check if it's a close match with character substitutions
            differences = sum(1 for a, b in zip(domain_without_tld, brand_lower) if a != b)
            if differences <= 2 and differences > 0:
                return True
        
        # Check normalized version
        if brand_lower in normalized_without_tld and normalized_without_tld != brand_lower:
            return True
    
    return False


def analyze_html_content(html: str, base_url: str) -> Dict:
    """
    Analyze HTML content for phishing indicators.
    
    Returns:
        dict with detected features and reasons
    """
    html_lower = html.lower()
    reasons = []
    score = 0
    
    # 1. Detect login forms (password inputs)
    password_input_pattern = r'<input[^>]*type\s*=\s*["\']?password["\']?[^>]*>'
    login_forms = re.findall(password_input_pattern, html, re.IGNORECASE)
    if login_forms:
        score += 25
        reasons.append("Login form detected (password input field)")
    
    # 2. Detect suspicious keywords in HTML content
    keyword_count = 0
    found_keywords = []
    for keyword in SUSPICIOUS_KEYWORDS:
        # Use word boundaries to avoid partial matches
        pattern = r'\b' + re.escape(keyword) + r'\b'
        matches = re.findall(pattern, html_lower)
        if matches:
            keyword_count += len(matches)
            if keyword not in found_keywords:
                found_keywords.append(keyword)
    
    if keyword_count > 0:
        score += 10
        reasons.append(f"Suspicious keywords detected: {', '.join(found_keywords[:5])}")
    
    # 3. Detect urgent phrases
    urgent_count = 0
    found_phrases = []
    for phrase in URGENT_PHRASES:
        pattern = re.escape(phrase)
        if re.search(pattern, html_lower):
            urgent_count += 1
            found_phrases.append(phrase)
    
    if urgent_count > 0:
        score += 20
        reasons.append(f"Urgent/suspicious phrases detected: {', '.join(found_phrases[:3])}")
    
    # 4. Detect scripts from unknown domains
    script_pattern = r'<script[^>]*src\s*=\s*["\']([^"\']+)["\']'
    scripts = re.findall(script_pattern, html, re.IGNORECASE)
    
    try:
        base_domain = urlparse(base_url).netloc
        base_domain_parts = tldextract.extract(base_domain)
        base_domain_normalized = f"{base_domain_parts.domain}.{base_domain_parts.suffix}"
    except:
        base_domain_normalized = ""
    
    unknown_scripts = []
    for script_url in scripts:
        try:
            # Handle relative URLs
            if script_url.startswith('//'):
                script_url = 'http:' + script_url
            elif script_url.startswith('/'):
                script_url = urljoin(base_url, script_url)
            elif not script_url.startswith(('http://', 'https://')):
                script_url = urljoin(base_url, script_url)
            
            script_domain = urlparse(script_url).netloc
            script_domain_parts = tldextract.extract(script_domain)
            script_domain_normalized = f"{script_domain_parts.domain}.{script_domain_parts.suffix}"
            
            if script_domain_normalized and script_domain_normalized != base_domain_normalized:
                unknown_scripts.append(script_domain_normalized)
        except:
            pass
    
    if unknown_scripts:
        unique_unknown = list(set(unknown_scripts))[:3]
        score += 10
        reasons.append(f"Scripts loaded from external domains: {', '.join(unique_unknown)}")
    
    # 5. Detect forms that send POST requests to external URLs
    form_pattern = r'<form[^>]*action\s*=\s*["\']([^"\']+)["\']'
    forms = re.findall(form_pattern, html, re.IGNORECASE)
    
    external_forms = []
    for form_action in forms:
        try:
            # Handle relative URLs
            if form_action.startswith('//'):
                form_action = 'http:' + form_action
            elif form_action.startswith('/'):
                form_action = urljoin(base_url, form_action)
            elif not form_action.startswith(('http://', 'https://')):
                form_action = urljoin(base_url, form_action)
            
            form_domain = urlparse(form_action).netloc
            form_domain_parts = tldextract.extract(form_domain)
            form_domain_normalized = f"{form_domain_parts.domain}.{form_domain_parts.suffix}"
            
            if form_domain_normalized and form_domain_normalized != base_domain_normalized:
                external_forms.append(form_domain_normalized)
        except:
            pass
    
    if external_forms:
        unique_external = list(set(external_forms))[:3]
        score += 15
        reasons.append(f"Form submits to external domain: {', '.join(unique_external)}")
    
    return {
        "score": min(score, 100),
        "reasons": reasons
    }


def analyze_domain(url: str) -> Dict:
    """
    Analyze domain for phishing indicators.
    
    Returns:
        dict with detected features and reasons
    """
    reasons = []
    score = 0
    
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        tld = f".{extracted.suffix}"
        
        # Check for suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            score += 20
            reasons.append(f"Suspicious TLD detected: {tld}")
        
        # Check for lookalike domains
        if detect_lookalike_domain(domain):
            score += 20
            reasons.append(f"Domain appears to be a lookalike of a popular brand")
        
    except Exception as e:
        # If domain extraction fails, it's suspicious
        score += 10
        reasons.append("Unable to properly parse domain")
    
    return {
        "score": min(score, 100),
        "reasons": reasons
    }


async def fetch_html(url: str) -> str:
    """
    Fetch HTML content from URL.
    
    Returns:
        str: HTML content, or empty string if fetch fails
    """
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            response.raise_for_status()
            return response.text
    except Exception:
        return ""


async def analyze_with_ai(url: str, html: str = None) -> dict:
    """
    Analyze URL and HTML content for phishing risk using AI-powered heuristics.
    
    Args:
        url: The URL to analyze
        html: Optional HTML content. If not provided, will be fetched from URL.
    
    Returns:
        {
            "ai_score": int (0-100),
            "ai_label": str ("safe" | "suspicious" | "phishing"),
            "ai_reasons": List[str]
        }
    """
    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    all_reasons = []
    total_score = 0
    
    # Fetch HTML if not provided
    if html is None:
        html = await fetch_html(url)
    
    # Analyze HTML content
    if html:
        html_analysis = analyze_html_content(html, url)
        total_score += html_analysis["score"]
        all_reasons.extend(html_analysis["reasons"])
    
    # Analyze domain
    domain_analysis = analyze_domain(url)
    total_score += domain_analysis["score"]
    all_reasons.extend(domain_analysis["reasons"])
    
    # Cap score at 100
    total_score = min(total_score, 100)
    
    # Determine label based on score
    if total_score >= 60:
        label = "phishing"
    elif total_score >= 30:
        label = "suspicious"
    else:
        label = "safe"
    
    return {
        "ai_score": total_score,
        "ai_label": label,
        "ai_reasons": all_reasons
    }


