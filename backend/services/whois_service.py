import threading

def get_live_domain_age(domain: str) -> int:
    result = [0]

    def _fetch():
        try:
            import whois
            w = whois.whois(domain)
            if w.creation_date:
                created = w.creation_date
                if isinstance(created, list):
                    created = created[0]
                from datetime import datetime
                result[0] = (datetime.now() - created).days
        except Exception:
            pass

    t = threading.Thread(target=_fetch)
    t.start()
    t.join(timeout=3)   # give WHOIS max 3 seconds, then move on
    return result[0]