import socket
import ssl
from datetime import datetime, timezone

import tldextract
import whois


def get_domain_and_host(url: str):
    """
    Extract the registrable domain and host from a URL.
    """
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    host = domain
    return domain, host


def get_domain_age_days(url: str) -> dict:
    """
    Return domain creation date and age in days, with robust error handling.
    """
    domain, _ = get_domain_and_host(url)
    try:
        w = whois.whois(domain)
        created = w.creation_date

        # whois returns either single datetime or list; normalize
        if isinstance(created, list):
            created = created[0]

        if not created:
            return {
                "created": None,
                "age_days": None,
                "error": "Created date not found",
            }

        # ensure timezone-aware
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age = (now - created).days

        return {
            "created": created.isoformat(),
            "age_days": age,
            "error": None,
        }
    except Exception as e:
        return {
            "created": None,
            "age_days": None,
            "error": str(e),
        }


def get_ssl_info(url: str, timeout: int = 8) -> dict:
    """
    Fetch SSL certificate details for the given URL's host.
    """
    _, host = get_domain_and_host(url)
    port = 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)

        from cryptography import x509

        cert = x509.load_der_x509_certificate(cert_bin)
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after

        return {
            "issuer": issuer,
            "subject": subject,
            "valid_from": not_before.isoformat(),
            "valid_to": not_after.isoformat(),
            "error": None,
        }
    except Exception as e:
        return {
            "issuer": None,
            "subject": None,
            "valid_from": None,
            "valid_to": None,
            "error": str(e),
        }



