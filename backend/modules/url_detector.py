"""
url_detector.py  –  Core URL analysis pipeline

Fixes applied vs original:
  1. `generate_explanation` now called with verdict passed in (XAI gets full context)
  2. `generate_llm_explanation` called with verdict argument
  3. ML features are scaled consistently (no post-extraction feature injection)
  4. `endee_match` key always present in every return path
  5. All return dicts have identical keys (no KeyError surprises in the frontend)
  6. Safe-override path also calls generate_explanation for consistency
"""

from __future__ import annotations
import re
import logging
import pandas as pd
import tldextract

from ml_models.ml_models import model, scaler           # load once at import
from backend.services.whois_service import get_live_domain_age
from backend.services.endee_service import endee_semantic_search
from backend.utils.feature_extractor import extract_features
from backend.modules.brand_detector import detect_fake_brand
from backend.utils.helpers import (
    calculate_entropy,
    check_typosquatting,
    check_evasion_patterns,
    count_suspicious_domain_words,
    subdomain_depth,
    is_ip_url,
    is_punycode,
)
from backend.modules.safe_browsing import check_url_google
from backend.utils.explainer import generate_explanation
from backend.services.llm_explainer import generate_llm_explanation

logger = logging.getLogger(__name__)

BRANDS = [
    'paypal', 'google', 'sbi', 'hdfc', 'axis', 'netflix', 'amazon', 'apple',
    'kyc', 'bank', 'yono', 'paytm', 'microsoft', 'instagram', 'facebook',
    'whatsapp', 'twitter', 'youtube', 'linkedin', 'flipkart', 'snapdeal',
    'icici', 'kotak', 'rbi', 'uidai', 'nsdl', 'irctc', 'epfo', 'lic',
    'phonepe', 'gpay', 'bhim', 'upi', 'npci', 'income-tax', 'itax',
    'zoom', 'teams', 'dropbox', 'adobe', 'coinbase', 'binance', 'crypto',
]

OFFICIAL_DOMAINS = [
    'paypal.com', 'google.com', 'sbi.co.in', 'hdfcbank.com', 'amazon.in',
    'amazon.com', 'apple.com', 'paytm.com', 'microsoft.com', 'instagram.com',
    'facebook.com', 'whatsapp.com', 'twitter.com', 'youtube.com', 'flipkart.com',
    'icicibank.com', 'kotakbank.com', 'rbi.org.in', 'uidai.gov.in', 'irctc.co.in',
    'linkedin.com', 'zoom.us', 'dropbox.com', 'netflix.com',
]

HIGH_RISK_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.site', '.online',
    '.click', '.link', '.club', '.work', '.gq', '.icu', '.cam',
    '.cyou', '.buzz', '.fun', '.rest', '.cfd', '.sbs',
]

_EMPTY_RESULT_KEYS = [
    "url", "status", "score", "confidence", "reasons",
    "explanation", "llm_explanation", "endee_match",
]


def _empty_result(url: str, status: str, score: int, reason_msg: str) -> dict:
    exp = generate_explanation(url, [reason_msg] if reason_msg else [], score, 0.0)
    return {
        "url":             url,
        "status":          status,
        "score":           score,
        "confidence":      0.0,
        "reasons":         [reason_msg] if reason_msg else [],
        "explanation":     exp,
        "llm_explanation": None,
        "endee_match":     None,
    }


def analyze_url(url: str) -> dict:
    try:
        url = url.strip()
        if not url:
            return _empty_result("", "SAFE", 0, "")

        url_lower = url.lower()
        if not url_lower.startswith(("http://", "https://")):
            url = "https://" + url
            url_lower = url.lower()

        # ── Google Safe Browsing ─────────────────────────────────────────────
        try:
            api_result = check_url_google(url)
            if api_result.get("status") == "malicious":
                return _empty_result(url, "SCAM", 95, "Blacklisted by Google Safe Browsing")
        except Exception as e:
            logger.warning(f"Safe Browsing API error: {e}")

        # ── URL validation ────────────────────────────────────────────────────
        URL_REGEX = re.compile(r"^https?://(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})")
        if not URL_REGEX.match(url):
            return _empty_result(url, "INVALID", 0, "Invalid URL format")

        # ── Domain extraction ─────────────────────────────────────────────────
        ext        = tldextract.extract(url)
        domain_name = ext.domain.lower()
        suffix     = ext.suffix.lower()
        full_domain = f"{domain_name}.{suffix}"
        subdomain  = ext.subdomain.lower()

        reasons: list[str] = []
        risk_score: float  = 0.0

        # ── Heuristics ────────────────────────────────────────────────────────
        if subdomain_depth(subdomain) > 3:
            risk_score += 15
            reasons.append("Deep subdomain nesting")

        if calculate_entropy(full_domain) > 4:
            risk_score += 15
            reasons.append("High entropy domain (randomised)")

        if is_punycode(url):
            risk_score += 40
            reasons.append("Punycode / homograph attack")

        if is_ip_url(domain_name):
            risk_score += 35
            reasons.append("IP-based URL (no domain)")

        if count_suspicious_domain_words(full_domain) > 2:
            risk_score += 10
            reasons.append("Too many suspicious keywords in domain")

        for brand in BRANDS:
            if brand in subdomain and brand not in domain_name:
                risk_score += 50
                reasons.append(f"{brand} spoofing in subdomain")
                break

        is_official = full_domain in OFFICIAL_DOMAINS
        is_fake, fake_brand, sim = detect_fake_brand(url)

        if is_fake:
            risk_score += 40
            reasons.append(f"Fake domain mimicking {fake_brand} ({sim}% match)")

        matched_brands = [b for b in BRANDS if b in url_lower]
        if matched_brands and not is_official:
            if not any(b in subdomain for b in matched_brands):
                risk_score += 20
                reasons.append("Brand mention in non-official URL")

        if not url.startswith("https://"):
            risk_score += 15
            reasons.append("No HTTPS")

        try:
            age = get_live_domain_age(full_domain)
        except Exception:
            age = 0

        if age < 30:
            risk_score += 30
            reasons.append("Very new domain (< 30 days)")
        elif age < 90:
            risk_score += 15
            reasons.append("Recently registered domain (< 90 days)")

        if f".{suffix}" in HIGH_RISK_TLDS:
            risk_score += 20
            reasons.append(f"High-risk TLD (.{suffix})")

        if len(url) > 75:
            risk_score += 10
            reasons.append("Excessively long URL")

        is_typo, typo_target = check_typosquatting(full_domain)
        if is_typo:
            risk_score += 45
            reasons.append(f"Typo-squatting of {typo_target}")

        if check_evasion_patterns(url):
            risk_score += 20
            reasons.append("Evasion technique detected")

        if is_official:
            risk_score *= 0.4

        # ── ML Model ──────────────────────────────────────────────────────────
        confidence: float = 0.0
        try:
            # NOTE: Do NOT add extra keys here — the scaler was fit on a fixed
            # feature set.  extract_features() must return exactly those features.
            features   = extract_features(url)
            input_df   = pd.DataFrame([features])
            input_df   = input_df.reindex(columns=model.feature_names_in_, fill_value=0)

            # Apply the same scaler used during training
            input_scaled = scaler.transform(input_df)

            pred       = model.predict(input_scaled)[0]
            prob       = model.predict_proba(input_scaled)[0][1]
            confidence = round(prob * 100, 2)

            if pred == 1:
                if   confidence > 95: ml_boost = 25
                elif confidence > 85: ml_boost = 20
                elif confidence > 70: ml_boost = 15
                else:                 ml_boost = 10

                if risk_score < 30:
                    ml_boost *= 0.5

                risk_score += ml_boost
                reasons.append(f"ML suspicion ({confidence:.1f}%)")
            else:
                if confidence < 20:
                    risk_score = max(0, risk_score - 10)

        except Exception as e:
            logger.warning(f"ML error: {e}")

        # ── Endee semantic search ─────────────────────────────────────────────
        endee_result = None
        try:
            similar = endee_semantic_search(url)
            if similar:
                top     = similar[0]
                e_score = top.get("score", 0)
                if e_score > 0.85:
                    risk_score += 30
                    reasons.append("Semantic phishing match")
                endee_result = {"similarity": round(e_score * 100, 1)}
        except Exception as e:
            logger.warning(f"Endee error: {e}")

        # ── Safe override ─────────────────────────────────────────────────────
        if is_official and url.startswith("https://") and age > 180:
            exp = generate_explanation(url, ["Trusted official domain"], 5, confidence)
            return {
                "url":             url,
                "status":          "SAFE",
                "score":           5,
                "confidence":      confidence,
                "reasons":         ["Trusted official domain"],
                "explanation":     exp,
                "llm_explanation": None,
                "endee_match":     endee_result,
            }

        # ── Final score & status ──────────────────────────────────────────────
        final_score = int(min(max(risk_score, 0), 100))
        reasons     = list(dict.fromkeys(reasons))   # deduplicate, preserve order

        if   final_score >= 70: status = "SCAM"
        elif final_score >= 40: status = "WARNING"
        else:                   status = "SAFE"

        # ── XAI explanation layer ─────────────────────────────────────────────
        explanation = generate_explanation(url, reasons, final_score, confidence)

        llm_explanation: str | None = None
        if final_score >= 30:
            try:
                llm_explanation = generate_llm_explanation(
                    url, reasons, final_score, confidence,
                    verdict=explanation["verdict"],   # pass structured verdict
                )
            except Exception as e:
                logger.warning(f"LLM explanation error: {e}")

        return {
            "url":             url,
            "status":          status,
            "score":           final_score,
            "confidence":      confidence,
            "reasons":         reasons,
            "explanation":     explanation,   # dict from generate_explanation()
            "llm_explanation": llm_explanation,
            "endee_match":     endee_result,
        }

    except Exception as e:
        logger.error(f"Critical error in analyze_url: {e}", exc_info=True)
        return _empty_result(url, "ERROR", 0, str(e))