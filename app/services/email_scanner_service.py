# src/services/email_scanner_service.py
import re
import math
from typing import List, Dict, Any, Optional

import tldextract

from app.services.url_scanner_service import scan_url_service
from app.services.redirect_chain_service import get_redirect_chain
from app.services.domain_ssl_service import get_domain_age

FREE_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "icloud.com",
}


def _extract_urls_from_text(text: str) -> List[str]:
    url_pattern = r"https?://[^\s'\"<>]+"
    return re.findall(url_pattern, text or "")


def _levenshtein(a: str, b: str) -> int:
    a = a or ""
    b = b or ""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


async def _analyze_urls(urls: List[str]) -> List[Dict[str, Any]]:
    per_url_reports: List[Dict[str, Any]] = []
    for raw_url in urls[:20]:  # allow more in email analyzer but still capped
        try:
            scan_result = await scan_url_service(raw_url)
            redirect_chain = await get_redirect_chain(raw_url)
            report = {
                "url": scan_result.get("url", raw_url),
                "label": scan_result.get("label") or "unknown",
                "rule_based_score": scan_result.get("score"),
                "final_score": scan_result.get("score"),
                "reasons": scan_result.get("reasons", []),
                "domain_age": scan_result.get("domain_age"),
                "ssl_info": scan_result.get("ssl_info"),
                "redirect_chain": redirect_chain or {"chain": []},
            }
        except Exception as exc:
            report = {
                "url": raw_url,
                "label": "error",
                "rule_based_score": None,
                "final_score": None,
                "reasons": [f"URL scan failed: {str(exc)}"],
                "domain_age": None,
                "ssl_info": None,
                "redirect_chain": {"chain": []},
            }
        per_url_reports.append(report)
    return per_url_reports


def _analyze_sender_domain(sender: str) -> Dict[str, Any]:
    sender_report: Dict[str, Any] = {}
    if not sender:
        sender_report["present"] = False
        sender_report["notes"] = ["No sender address provided for analysis."]
        return sender_report

    sender_report["present"] = True
    sender_report["address"] = sender
    domain_part = sender.split("@")[-1].lower() if "@" in sender else ""
    sender_report["domain"] = domain_part or None

    if domain_part in FREE_PROVIDERS:
        sender_report["email_type"] = "free_provider"
        sender_report.setdefault("warnings", []).append(
            "Sender uses a free email provider; these are commonly abused for phishing."
        )
    elif domain_part:
        sender_report["email_type"] = "business_or_custom"

    if domain_part:
        try:
            domain_age = get_domain_age(domain_part)
        except Exception as exc:
            domain_age = {"age_days": None, "error": str(exc)}
        sender_report["domain_age"] = domain_age
    else:
        sender_report["domain_age"] = None

    sender_report["spf"] = {"status": "unknown", "details": "SPF not checked in this service."}
    sender_report["dmarc"] = {"status": "unknown", "details": "DMARC not checked in this service."}
    sender_report["dkim"] = {"status": "unknown", "details": "DKIM not checked in this service."}

    return sender_report


async def scan_email_service(
    subject: str = "",
    sender: str = "",
    body: str = "",
    links: List[str] | None = None,
    attachments: List[Dict[str, Any]] | None = None,
    raw_headers: Optional[str] = None,
) -> Dict[str, Any]:
    links = links or []
    attachments = attachments or []

    # 1. extract urls from subject/body
    extracted_from_body = _extract_urls_from_text(body)
    extracted_from_subject = _extract_urls_from_text(subject)
    all_urls: List[str] = []
    seen = set()
    for u in links + extracted_from_subject + extracted_from_body:
        if not u:
            continue
        if u not in seen:
            seen.add(u)
            all_urls.append(u)

    # 2. per-url analysis
    per_url_reports = await _analyze_urls(all_urls)

    # 3. sender domain analysis
    sender_report = _analyze_sender_domain(sender)

    # ---------- Rule-based scoring ----------
    url_component = 0
    url_reasons = []
    for rep in per_url_reports:
        url_score = rep.get("final_score") or rep.get("rule_based_score") or 0
        try:
            url_score = int(url_score)
        except Exception:
            url_score = 0
        url_component = max(url_component, url_score)
        if rep.get("label") in ("phishing", "malicious"):
            url_reasons.append(f"Linked URL flagged: {rep.get('url')}")

    # Sender domain age
    sender_age_days = None
    if sender_report.get("domain_age") and isinstance(sender_report["domain_age"], dict):
        sender_age_days = sender_report["domain_age"].get("age_days")
    sender_component = 0
    if isinstance(sender_age_days, int):
        if sender_age_days < 30:
            sender_component = 30
            url_reasons.append("Sender domain very new (<30 days)")
        elif sender_age_days < 180:
            sender_component = 15

    # attachments
    attachment_component = 0
    attachment_reasons = []
    for a in attachments:
        filename = a.get("filename", "").lower()
        ext = filename.split(".")[-1] if "." in filename else ""
        if ext in ("exe", "scr", "js", "hta", "vbs", "bat", "msi", "cmd", "jar"):
            attachment_component = max(attachment_component, 30)
            attachment_reasons.append(f"Suspicious attachment type: .{ext}")
        elif ext in ("zip", "rar"):
            attachment_component = max(attachment_component, 12)
            attachment_reasons.append(f"Archive attachment: .{ext}")

    # subject/body heuristics
    subj_body_component = 0
    subj_body_reasons = []
    combined_text = f"{subject or ''}\n{body or ''}".lower()
    if re.search(r"\burgent\b|\bimmediate\b|\bverify\b|\baction required\b|\bsuspend(ed)?\b", combined_text):
        subj_body_component += 15
        subj_body_reasons.append("Urgency language detected")
    if re.search(r"enter (your )?password|provide (your )?password|confirm (your )?account|update billing|verify payment", combined_text):
        subj_body_component += 25
        subj_body_reasons.append("Explicit credential/payment request language detected")
    
    keyword_hits = sum(1 for k in ["password", "bank", "billing", "invoice", "verify", "suspend", "secure", "confirm"] if k in combined_text)
    subj_body_component += min(10, keyword_hits * 3)

    # impersonation heuristics
    impersonation_score = 0
    impersonation_reasons = []
    try:
        display_name = ""
        m = re.match(r'^(.*)<([^>]+)>', sender or "")
        if m:
            display_name = m.group(1).strip().strip('"').strip()
        else:
            if "@" in sender:
                display_name = sender.split("@")[0]
    except Exception:
        display_name = ""

    if display_name and "@" in sender:
        send_local = sender.split("@")[0].lower()
        if display_name and len(display_name) >= 4:
            dist = _levenshtein(re.sub(r"\W+", "", display_name.lower()), re.sub(r"\W+", "", send_local.lower()))
            if dist > max(3, int(0.2 * max(len(display_name), len(send_local)))):
                impersonation_score += 8
                impersonation_reasons.append("Display name and email local part do not match (possible impersonation)")

    # Compose rule_based_score
    scaled_sender = min(100, int((sender_component / 30) * 100)) if sender_component else 0
    scaled_attach = min(100, int((attachment_component / 30) * 100)) if attachment_component else 0
    scaled_subj_body = min(100, int((subj_body_component / 30) * 100)) if subj_body_component else 0
    scaled_impersonation = min(100, int((impersonation_score / 30) * 100)) if impersonation_score else 0

    others_weighted = int((0.35 * scaled_sender) + (0.25 * scaled_attach) + (0.25 * scaled_subj_body) + (0.15 * scaled_impersonation))
    rule_based_score = max(int(url_component), others_weighted)

    rule_reasons = []
    rule_reasons.extend(url_reasons)
    rule_reasons.extend(attachment_reasons)
    rule_reasons.extend(subj_body_reasons)
    rule_reasons.extend(impersonation_reasons)

    # Final score (no AI for now)
    final_score = rule_based_score

    # Heuristic boosts
    heuristic_boost = 0
    if any((rep.get("label") in ("phishing", "malicious") or (rep.get("final_score") and int(rep.get("final_score", 0)) >= 80)) for rep in per_url_reports):
        heuristic_boost += 20
    
    first_link_domain = None
    if per_url_reports:
        first_url = per_url_reports[0].get("url") or ""
        if first_url:
            ex = tldextract.extract(first_url)
            if ex.suffix:
                first_link_domain = f"{ex.domain}.{ex.suffix}".lower()
            else:
                first_link_domain = ex.domain.lower()
    sender_domain = sender.split("@")[-1].lower() if "@" in sender else None
    if sender_domain and first_link_domain and sender_domain != first_link_domain:
        heuristic_boost += 10

    if any((a.get("filename", "").lower().endswith(ext) for a in attachments for ext in [".exe", ".js", ".hta", ".scr", ".vbs", ".msi"])):
        heuristic_boost += 20

    final_score = max(0, min(100, final_score + heuristic_boost))

    # Label - Using standardized thresholds (60/30) matching URL scanner
    if final_score >= 60:
        final_label = "phishing"
        summary = "High likelihood of phishing."
    elif final_score >= 30:
        final_label = "suspicious"
        summary = "Multiple suspicious indicators found."
    else:
        final_label = "safe"
        summary = "No strong phishing indicators detected."

    recommendations = []
    if final_label != "safe":
        recommendations.append("Do not click links or open attachments until sender is validated.")
    if per_url_reports:
        recommendations.append("Hover over links to verify real domains and report suspicious URLs to Security.")
    if sender_report.get("email_type") == "free_provider":
        recommendations.append("Double-check requests from free email providers that claim to be official.")

    result = {
        "summary": summary,
        "rule_based_score": rule_based_score,
        "rule_based_reasons": rule_reasons,
        "per_url_reports": per_url_reports,
        "sender_domain_report": sender_report,
        "final_email_risk_score": final_score,
        "final_email_risk_label": final_label,
        "recommendations": recommendations,
        "combined_indicators": rule_reasons,
    }

    return result
