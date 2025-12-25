
import whois
import datetime

domain = "google.com"
print(f"Testing WHOIS for {domain}...")

try:
    w = whois.whois(domain)
    print("WHOIS raw:", w)
    
    created = w.creation_date
    print("Creation Date raw:", created)
    
    if isinstance(created, list):
        created = created[0]
        
    print("Creation Date final:", created)
except Exception as e:
    print("Error:", e)
