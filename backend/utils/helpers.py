import math
import re
from backend.utils.constants import (
    ABUSED_LEGIT_HOSTS, SUSPICIOUS_PATH_WORDS,
    TYPOSQUAT_TARGETS, EVASION_PATTERNS, SUSPICIOUS_DOMAIN_WORDS
)

# ─────────────────────────────────────────────
# 🔢 ENTROPY (Random Domain Detection)
# ─────────────────────────────────────────────

def calculate_entropy(text: str) -> float:
    """Shannon entropy of a string — high entropy → random/obfuscated domain."""
    if not text:
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)


def is_high_entropy(domain: str, threshold: float = 3.5) -> bool:
    """Detects random-looking domains (DGA domains)."""
    return calculate_entropy(domain) > threshold


# ─────────────────────────────────────────────
# 🎭 TYPOSQUATTING DETECTION
# ─────────────────────────────────────────────

def check_typosquatting(domain_part: str):
    """
    Returns (True, legit_brand) if domain_part matches a known typosquat variant,
    otherwise (False, None).
    """
    for legit, variants in TYPOSQUAT_TARGETS:
        if any(v in domain_part for v in variants):
            return True, legit
    return False, None


# ─────────────────────────────────────────────
# 🏢 ABUSED LEGITIMATE HOSTS (GitHub, Firebase, etc.)
# ─────────────────────────────────────────────

def check_abused_legitimate(url: str):
    """
    Returns (is_abused, path_hits, host) if URL uses a trusted platform
    with suspicious path keywords.
    """
    for host in ABUSED_LEGIT_HOSTS:
        if host in url:
            path = url.split(host)[-1]
            path_hits = sum(1 for w in SUSPICIOUS_PATH_WORDS if w in path)
            return True, path_hits, host
    return False, 0, None


# ─────────────────────────────────────────────
# 🕵️ EVASION PATTERNS (URL Tricks)
# ─────────────────────────────────────────────

def check_evasion_patterns(url: str):
    """Returns list of (label, pattern) tuples for matched evasion techniques."""
    return [(label, p) for p, label in EVASION_PATTERNS if re.search(p, url)]


# ─────────────────────────────────────────────
# ⚠️ SUSPICIOUS DOMAIN WORDS
# ─────────────────────────────────────────────

def count_suspicious_domain_words(domain_name: str) -> int:
    """Counts how many suspicious keywords appear in the domain name."""
    return sum(1 for w in SUSPICIOUS_DOMAIN_WORDS if w in domain_name)


# ─────────────────────────────────────────────
# 🌐 SUBDOMAIN DEPTH (Phishing Trick)
# ─────────────────────────────────────────────

def subdomain_depth(subdomain: str) -> int:
    """Returns number of subdomain levels."""
    if not subdomain:
        return 0
    return len([s for s in subdomain.split('.') if s])


# ─────────────────────────────────────────────
# 🧬 PUNYCODE (Homograph Attack)
# ─────────────────────────────────────────────

def is_punycode(url: str) -> int:
    """Detects IDN homograph attack (xn-- domains)."""
    return 1 if "xn--" in url.lower() else 0


# ─────────────────────────────────────────────
# 🌍 IP-BASED URL DETECTION
# ─────────────────────────────────────────────

def is_ip_url(domain: str) -> bool:
    """Checks if domain itself is an IP address."""
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))


# ─────────────────────────────────────────────
# 🏷️ BRAND SPOOFING (CRITICAL FEATURE 🔥)
# ─────────────────────────────────────────────

def is_brand_in_subdomain(subdomain: str, domain_name: str, brands: list):
    """
    Detects phishing like:
    paypal.secure-login.xyz (brand in subdomain, not in main domain)
    """
    for brand in brands:
        if brand in subdomain and brand not in domain_name:
            return True, brand
    return False, None