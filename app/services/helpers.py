from datetime import datetime

def safe_parse_whois_date(value):
    """
    Safely parse WHOIS date formats into a timezone-aware datetime.
    Returns None if parsing fails.
    """
    if not value:
        return None

    if isinstance(value, datetime):
        # Make timezone-aware if it is not
        if value.tzinfo is None:
            return value.replace(tzinfo=datetime.utcnow().astimezone().tzinfo)
        return value

    try:
        parsed = datetime.strptime(value, "%Y-%m-%d")
        return parsed.replace(tzinfo=datetime.utcnow().astimezone().tzinfo)
    except:
        pass

    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        return parsed.replace(tzinfo=datetime.utcnow().astimezone().tzinfo)
    except:
        pass

    # Last fallback: try flexible parser
    try:
        from dateutil import parser
        parsed = parser.parse(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.utcnow().astimezone().tzinfo)
        return parsed
    except:
        return None