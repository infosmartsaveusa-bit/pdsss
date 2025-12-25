import socket
import ssl
import datetime
import whois

def get_domain_age(domain):
    try:
        w = whois.whois(domain)

        # Some WHOIS providers return lists
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        if not created:
            return {"created": "Unknown", "age_days": "Unknown"}

        # Normalize timezone-aware / naive datetime
        if created.tzinfo is None:
            created = created.replace(tzinfo=datetime.timezone.utc)

        now = datetime.datetime.now(datetime.timezone.utc)
        age_days = (now - created).days

        return {
            "created": created.strftime("%Y-%m-%d"),
            "age_days": age_days
        }

    except Exception as e:
        return {"created": "Unknown", "age_days": "Unknown", "error": str(e)}


def get_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

        valid_from = cert["notBefore"]
        valid_to = cert["notAfter"]
        
        # Format issuer as readable string
        issuer_raw = cert.get("issuer")
        issuer_str = "Unknown"
        
        if issuer_raw:
            # issuer is a tuple of tuples like ((('countryName', 'US'),), (('organizationName', 'Google Trust Services'),), ...)
            issuer_parts = {}
            for rdn in issuer_raw:
                for name_tuple in rdn:
                    if len(name_tuple) == 2:
                        issuer_parts[name_tuple[0]] = name_tuple[1]
            
            # Build readable string: "Organization - Common Name"
            org = issuer_parts.get('organizationName', '')
            cn = issuer_parts.get('commonName', '')
            
            if org and cn:
                issuer_str = f"{org} - {cn}"
            elif org:
                issuer_str = org
            elif cn:
                issuer_str = cn

        return {
            "issuer": issuer_str,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "valid": True,
        }

    except Exception as e:
        return {
            "issuer": "Unknown",
            "valid_from": None,
            "valid_to": None,
            "valid": False,
            "error": str(e)
        }