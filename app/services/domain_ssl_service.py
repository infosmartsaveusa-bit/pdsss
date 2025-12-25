import socket
import ssl
from datetime import datetime

import whois


def get_domain_age(domain: str):
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {"age_days": None, "error": "No creation date found"}

        age_days = (datetime.now() - creation_date).days

        return {
            "age_days": age_days,
            "creation_date": str(creation_date),
            "error": None,
        }
    except Exception as e:
        return {"age_days": None, "error": str(e)}


def get_ssl_info(domain: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = cert.get("issuer")
        valid_from = cert.get("notBefore")
        valid_to = cert.get("notAfter")

        return {
            "issuer": issuer,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "error": None,
        }

    except Exception as e:
        return {
            "issuer": None,
            "valid_from": None,
            "valid_to": None,
            "error": str(e),
        }


