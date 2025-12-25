"""
AI-Powered Phishing Analyzer Module

This module provides text and DOM analysis capabilities for detecting phishing attempts.
It includes fuzzy domain detection, text-based phishing indicators, and HTML/DOM structure analysis.
"""

import re
from difflib import SequenceMatcher
from typing import Dict, List, Tuple
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


# Known brand domains for lookalike detection
KNOWN_BRANDS = [
    "google", "paypal", "amazon", "icloud", "microsoft", "apple", 
    "facebook", "instagram", "twitter", "linkedin", "ebay", "walmart",
    "bankofamerica", "chase", "wellsfargo", "citibank", "hsbc"
]

# Character substitution map for detecting lookalike domains
CHAR_SUBSTITUTIONS = {
    'o': ['0'], '0': ['o'],
    'l': ['1', 'i'], '1': ['l', 'i'], 'i': ['l', '1'],
    's': ['5'], '5': ['s'],
    'a': ['@'], '@': ['a'],
    'e': ['3'], '3': ['e'],
    't': ['7'], '7': ['t'],
    'b': ['6'], '6': ['b'],
    'g': ['9'], '9': ['g'],
    'z': ['2'], '2': ['z']
}

# Phishing keywords that increase risk score
PHISHING_KEYWORDS = [
    "urgent", "immediate", "act now", "limited time", "expires soon",
    "verify", "confirm", "update", "validate", "authenticate",
    "account", "login", "signin", "password", "credentials",
    "click here", "verify now", "confirm now", "update now",
    "suspended", "locked", "disabled", "restricted",
    "bank", "paypal", "amazon", "icloud", "microsoft", "apple",
    "win", "winner", "prize", "reward", "congratulations"
]

# Suspicious form field names that indicate phishing
SUSPICIOUS_FORM_FIELDS = [
    "password", "passwd", "pwd", "ssn", "social", "security", 
    "credit", "card", "cvv", "pin", "otp", "token", "confirm password"
]

# Suspicious CTA phrases
SUSPICIOUS_CTA = [
    "click here", "verify now", "confirm now", "update now", 
    "proceed", "continue", "submit", "unlock", "restore"
]


def analyze_text(text: str) -> Dict:
    """
    Analyze text content for phishing indicators.
    
    Weighting:
    - Urgency keywords: 10 points each (max 30)
    - Phishing keywords: 5 points each (max 30)
    - Misspellings of brands: 20 points each (max 40)
    - Suspicious forms: 15 points each (max 30)
    - Suspicious CTAs: 10 points each (max 20)
    
    Args:
        text: Text content to analyze
        
    Returns:
        Dictionary with ai_score (0-100) and indicators list
    """
    score = 0
    indicators = []
    
    text_lower = text.lower()
    
    # Check for urgency/phishing keywords
    urgency_count = 0
    phishing_keyword_count = 0
    
    for keyword in PHISHING_KEYWORDS:
        if keyword in text_lower:
            if keyword in ["urgent", "immediate", "act now", "limited time", "expires soon"]:
                urgency_count += 1
                if urgency_count <= 3:  # Cap at 3 to prevent score inflation
                    score += 10
                    indicators.append(f"Urgency keyword detected: '{keyword}'")
            else:
                phishing_keyword_count += 1
                if phishing_keyword_count <= 6:  # Cap at 6 to prevent score inflation
                    score += 5
                    indicators.append(f"Phishing keyword detected: '{keyword}'")
    
    # Check for suspicious CTAs
    cta_count = 0
    for cta in SUSPICIOUS_CTA:
        if cta in text_lower:
            cta_count += 1
            if cta_count <= 2:  # Cap at 2 to prevent score inflation
                score += 10
                indicators.append(f"Suspicious CTA detected: '{cta}'")
    
    # Check for suspicious form references
    form_count = 0
    for field in SUSPICIOUS_FORM_FIELDS:
        if field in text_lower:
            form_count += 1
            if form_count <= 2:  # Cap at 2 to prevent score inflation
                score += 15
                indicators.append(f"Suspicious form field reference: '{field}'")
    
    # Check for brand misspellings
    brand_misspellings = []
    for brand in KNOWN_BRANDS:
        # Check direct misspellings with substitutions
        if is_lookalike(brand, [brand], CHAR_SUBSTITUTIONS):
            # Look for substituted versions in text
            for char, subs in CHAR_SUBSTITUTIONS.items():
                if char in brand:
                    for sub in subs:
                        substituted_brand = brand.replace(char, sub)
                        if substituted_brand in text_lower and brand not in text_lower:
                            brand_misspellings.append(substituted_brand)
                            
    # Score brand misspellings (max 40 points)
    for i, misspelled in enumerate(set(brand_misspellings)):  # Use set to deduplicate
        if i < 2:  # Cap at 2 to prevent score inflation
            score += 20
            indicators.append(f"Potential brand misspelling: '{misspelled}'")
    
    return {
        "ai_score": min(score, 100),
        "indicators": indicators
    }


def is_lookalike(domain: str, known_brand_list: List[str], substitutions: Dict[str, List[str]] = None) -> bool:
    """
    Detect if a domain is a lookalike of known brands using character substitution and similarity.
    
    Args:
        domain: Domain to check
        known_brand_list: List of legitimate brand names
        substitutions: Character substitution map
        
    Returns:
        Boolean indicating if domain is a lookalike
    """
    if substitutions is None:
        substitutions = CHAR_SUBSTITUTIONS
        
    domain_lower = domain.lower()
    
    # Direct match check
    for brand in known_brand_list:
        if domain_lower == brand:
            return False  # Not a lookalike if it's the actual brand
            
    # Similarity check using SequenceMatcher
    for brand in known_brand_list:
        similarity = SequenceMatcher(None, domain_lower, brand).ratio()
        if similarity >= 0.8:  # High similarity threshold
            return True
            
    # Character substitution check
    for brand in known_brand_list:
        # Create variations of the brand with substitutions
        variations = _generate_variations(brand, substitutions)
        if domain_lower in variations:
            return True
            
    return False


def _generate_variations(base_word: str, substitutions: Dict[str, List[str]]) -> set:
    """
    Generate possible variations of a word using character substitutions.
    
    Args:
        base_word: Word to generate variations for
        substitutions: Character substitution map
        
    Returns:
        Set of possible variations
    """
    variations = {base_word.lower()}
    
    # For each character that can be substituted
    for char, substitutes in substitutions.items():
        if char in base_word:
            # For each substitute character
            new_variations = set()
            for variation in variations:
                # Replace all instances of the character
                for sub in substitutes:
                    new_variation = variation.replace(char, sub)
                    new_variations.add(new_variation)
            variations.update(new_variations)
            
    return variations


def analyze_dom(html: str, base_url: str) -> Dict:
    """
    Analyze HTML/DOM structure for phishing indicators.
    
    Weighting:
    - External form actions: 25 points
    - Multiple input fields: 15 points
    - Invisible iframes: 20 points
    - Password fields: 10 points
    - Suspicious attributes: 10 points
    
    Args:
        html: HTML content to analyze
        base_url: Base URL for comparison
        
    Returns:
        Dictionary with ai_score (0-100) and indicators list
    """
    if not BeautifulSoup:
        return {
            "ai_score": 0,
            "indicators": ["BeautifulSoup not available for DOM analysis"]
        }
        
    score = 0
    indicators = []
    
    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception:
        return {
            "ai_score": 0,
            "indicators": ["Failed to parse HTML content"]
        }
    
    # Parse base URL for domain comparison
    try:
        base_domain = urlparse(base_url).netloc.lower()
    except Exception:
        base_domain = ""
    
    # Check forms
    forms = soup.find_all('form')
    external_form_count = 0
    password_field_count = 0
    
    for form in forms:
        # Check form action
        action = form.get('action', '')
        if action:
            try:
                action_domain = urlparse(action).netloc.lower()
                # If action points to external domain
                if action_domain and action_domain != base_domain:
                    external_form_count += 1
                    if external_form_count <= 2:  # Cap to prevent score inflation
                        score += 25
                        indicators.append(f"Form with external action detected: {action}")
            except Exception:
                # Malformed URL, treat as suspicious
                score += 15
                indicators.append(f"Form with malformed action URL: {action}")
                
        # Check for password fields
        password_fields = form.find_all('input', {'type': 'password'})
        password_field_count += len(password_fields)
        
    # Score password fields (max 20 points)
    if password_field_count > 0:
        score += min(password_field_count * 10, 20)
        indicators.append(f"Password fields detected: {password_field_count}")
    
    # Check for many input fields (indicative of data harvesting)
    all_inputs = soup.find_all('input')
    if len(all_inputs) > 10:
        score += 15
        indicators.append(f"Excessive input fields detected: {len(all_inputs)}")
        
    # Check for invisible iframes
    iframes = soup.find_all('iframe')
    hidden_iframe_count = 0
    
    for iframe in iframes:
        # Check for hidden iframes
        style = iframe.get('style', '').lower()
        width = iframe.get('width', '')
        height = iframe.get('height', '')
        
        if ('display:none' in style or 
            'visibility:hidden' in style or 
            width == '0' or height == '0' or
            (width == '' and height == '')):
            hidden_iframe_count += 1
            if hidden_iframe_count <= 2:  # Cap to prevent score inflation
                score += 20
                indicators.append("Hidden iframe detected")
    
    # Check for suspicious attributes
    suspicious_attrs = 0
    for tag in soup.find_all(True):  # Find all tags
        attrs = tag.attrs
        # Check for onload, onerror, etc. event handlers that could be malicious
        for attr in attrs:
            if attr.startswith('on') and 'script' in str(attrs[attr]).lower():
                suspicious_attrs += 1
                if suspicious_attrs <= 2:  # Cap to prevent score inflation
                    score += 10
                    indicators.append(f"Suspicious script attribute: {attr}")
                    
    return {
        "ai_score": min(score, 100),
        "indicators": indicators
    }


def analyze_page(url: str, html: str) -> Dict:
    """
    Combined analysis of text and DOM content for phishing detection.
    
    Final score weighting:
    - Text analysis: 40%
    - DOM analysis: 60%
    
    Args:
        url: URL of the page
        html: HTML content of the page
        
    Returns:
        Dictionary with combined ai_score (0-100) and consolidated indicators list
    """
    # Extract text content for analysis
    text_content = _extract_text_from_html(html) if html else ""
    
    # Perform text analysis
    text_result = analyze_text(text_content)
    text_score = text_result["ai_score"]
    
    # Perform DOM analysis
    dom_result = analyze_dom(html, url) if html else {"ai_score": 0, "indicators": []}
    dom_score = dom_result["ai_score"]
    
    # Combine scores with weighting
    # Text analysis contributes 40%, DOM analysis contributes 60%
    combined_score = min(int(text_score * 0.4 + dom_score * 0.6), 100)
    
    # Consolidate indicators
    all_indicators = list(set(text_result["indicators"] + dom_result["indicators"]))
    
    return {
        "ai_score": combined_score,
        "indicators": all_indicators
    }


def _extract_text_from_html(html: str) -> str:
    """
    Extract text content from HTML.
    
    Args:
        html: HTML content
        
    Returns:
        Plain text content
    """
    if not BeautifulSoup:
        # Fallback to regex if BeautifulSoup is not available
        # Remove script and style elements
        html = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html, flags=re.DOTALL | re.IGNORECASE)
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', html)
        # Clean up whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    
    try:
        soup = BeautifulSoup(html, 'html.parser')
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        return soup.get_text(separator=' ', strip=True)
    except Exception:
        return ""


# For backward compatibility with existing code
def analyze_with_ai(url: str, html: str) -> Dict:
    """
    Backward compatible wrapper for analyze_page.
    
    Args:
        url: URL of the page
        html: HTML content of the page
        
    Returns:
        Dictionary with ai_score and ai_details
    """
    result = analyze_page(url, html)
    return {
        "ai_score": result["ai_score"],
        "ai_details": result["indicators"]
    }