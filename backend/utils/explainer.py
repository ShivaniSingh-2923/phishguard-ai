"""
explainer.py  –  Rule-based XAI layer for URL phishing detector
"""

from __future__ import annotations

REASON_MAP = {
    "spoofing":         ("Brand impersonation",      "This site pretends to be a trusted brand (e.g. PayPal, Google, SBI) by copying its name in the URL."),
    "Punycode":         ("Homograph / Punycode",      "The URL uses look-alike Unicode characters (e.g. 'pаypal' with a Cyrillic 'а') to fool you into thinking it's a real site."),
    "IP-based":         ("Raw IP address",            "Real businesses use domain names. A raw IP address (e.g. http://192.168.1.1/login) is a classic phishing trick."),
    "entropy":          ("Randomised domain",         "The domain looks machine-generated (random strings of letters/numbers), which is common in automated phishing campaigns."),
    "TLD":              ("High-risk domain extension","This URL uses a free or cheap extension (.xyz, .tk, .top, etc.) that is disproportionately linked to phishing."),
    "ML suspicion":     ("AI pattern match",          "Our machine-learning model found statistical patterns in this URL that closely match known phishing URLs."),
    "Typo-squatting":   ("Typo-squatting",            "The domain is a deliberate misspelling of a well-known site (e.g. 'arnaz0n.com' instead of 'amazon.com')."),
    "Evasion":          ("Evasion technique",         "The URL contains tricks designed to bypass security filters, such as excessive redirects, encoded characters, or obfuscated paths."),
    "Deep subdomain":   ("Suspicious subdomain depth","Legitimate sites rarely need more than one or two subdomain levels. Deep nesting (e.g. login.secure.bank.evil.com) is used to disguise the real domain."),
    "Excessively long": ("Unusually long URL",        "Phishing URLs are often padded with extra characters or parameters to hide the true destination and confuse users."),
    "Brand mention":    ("Brand name in non-official URL", "A brand name appears in the URL, but the actual domain does not match the brand's official site."),
    "Semantic phishing":("Semantically similar to known phishing", "Our vector-search engine found this URL is highly similar to URLs previously confirmed as phishing."),
    "Blacklisted":      ("Google Safe Browsing hit",  "This URL is on Google's active blocklist of malicious or deceptive websites."),
    "suspicious keyword":("Suspicious keywords",      "Words like 'login', 'verify', 'secure', or 'update' in URLs are heavily exploited by phishers to create urgency."),
    "Too many suspicious": ("Keyword stuffing",       "Multiple high-risk keywords (login, verify, bank, secure) appear together — a common pattern in credential-harvesting pages."),
}

SCORE_BANDS = [
    (85, "CRITICAL",  "Almost certainly a phishing or scam page. Do not visit, click, or enter any information."),
    (70, "HIGH RISK", "Strong phishing signals detected. Treat as malicious unless you can verify this URL through an official channel."),
    (55, "SUSPICIOUS","Several warning signs present. Proceed only if you are certain of the source."),
    (40, "CAUTION",   "Some unusual characteristics detected. Worth double-checking before entering credentials."),
    (20, "LOW RISK",  "Minor irregularities noted but no strong phishing indicators."),
    (0,  "SAFE",      "No significant phishing signals found. This URL appears legitimate."),
]

SCORE_COLOUR = {
    "CRITICAL":   "danger",
    "HIGH RISK":  "danger",
    "SUSPICIOUS": "warning",
    "CAUTION":    "warning",
    "LOW RISK":   "info",
    "SAFE":       "success",
}


def _match_reason(reason: str) -> tuple[str, str]:
    """Return (short_label, human_explanation) for a raw reason string."""
    for keyword, (label, explanation) in REASON_MAP.items():
        if keyword.lower() in reason.lower():
            return label, explanation
    return "Suspicious indicator", f"Detected: {reason}"


def generate_explanation(url: str, reasons: list[str], score: int | float, confidence: float) -> dict:
    """
    Returns a structured XAI explanation dict with the following keys:

    - verdict        : str  – one-word verdict (SAFE / CAUTION / SUSPICIOUS / HIGH RISK / CRITICAL)
    - verdict_color  : str  – semantic colour key (success / info / warning / danger)
    - summary        : str  – one-sentence plain-English verdict
    - score          : int  – 0-100 risk score
    - confidence     : float – ML model confidence (0-100), 0 if ML unavailable
    - indicators     : list[dict]  – each has {label, explanation, raw}
    - positive_signals: list[str] – things that look legitimate
    - recommendation : str  – what the user should do
    """
    score = int(min(max(score, 0), 100))

    # ── Verdict band ──────────────────────────────────────────────────────────
    verdict = "SAFE"
    summary = ""
    for threshold, label, desc in SCORE_BANDS:
        if score >= threshold:
            verdict = label
            summary = desc
            break

    verdict_color = SCORE_COLOUR.get(verdict, "info")

    # ── Parse each reason into a rich indicator ───────────────────────────────
    indicators = []
    seen_labels: set[str] = set()
    for r in (reasons or []):
        label, explanation = _match_reason(r)
        if label not in seen_labels:
            seen_labels.add(label)
            indicators.append({"label": label, "explanation": explanation, "raw": r})

    # ── Positive signals (what looks OK) ─────────────────────────────────────
    positive_signals: list[str] = []
    url_lower = url.lower()
    if url_lower.startswith("https://"):
        positive_signals.append("Uses HTTPS encryption")
    if score < 40 and confidence < 30:
        positive_signals.append("ML model found no phishing pattern")
    if not any("brand" in r.lower() or "spoof" in r.lower() for r in (reasons or [])):
        positive_signals.append("No brand impersonation detected")
    if not any("ip" in r.lower() for r in (reasons or [])):
        positive_signals.append("Uses a proper domain name (not a raw IP)")

    # ── Recommendation ────────────────────────────────────────────────────────
    if verdict in ("CRITICAL", "HIGH RISK"):
        recommendation = (
            "Do NOT proceed. Close this page immediately. "
            "If you arrived here from an email or SMS, report it as phishing."
        )
    elif verdict == "SUSPICIOUS":
        recommendation = (
            "Avoid entering any personal information. "
            "Verify the URL through the official website or app before proceeding."
        )
    elif verdict == "CAUTION":
        recommendation = (
            "Double-check that this is the site you intended to visit. "
            "Look for the padlock icon and confirm the domain spelling."
        )
    elif verdict == "LOW RISK":
        recommendation = "Use normal caution. No strong red flags were found."
    else:
        recommendation = "This URL appears safe. Continue as normal."

    return {
        "verdict":          verdict,
        "verdict_color":    verdict_color,
        "summary":          summary,
        "score":            score,
        "confidence":       round(float(confidence), 1),
        "indicators":       indicators,
        "positive_signals": positive_signals,
        "recommendation":   recommendation,
    }