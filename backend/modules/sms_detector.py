import re
import logging
from backend.services.endee_service import endee_semantic_search

logger = logging.getLogger(__name__)

SMS_SCAM_VECTORS = {
    "kyc_block": {
        "keywords": ["kyc", "kyc update", "kyc expired", "kyc pending", "complete kyc",
                     "kyc verification", "kyc not done", "aadhar kyc", "pan kyc"],
        "score": 35, "label": "KYC fraud attempt"
    },
    "account_block": {
        "keywords": ["account blocked", "account suspended", "account deactivated",
                     "account on hold", "account frozen", "account closed"],
        "score": 40, "label": "Account block threat"
    },
    "bank_verify": {
        "keywords": ["bank verification", "verify bank", "bank account verify",
                     "net banking", "internet banking", "mobile banking update"],
        "score": 30, "label": "Bank verification scam"
    },
    "card_scam": {
        "keywords": ["debit card blocked", "credit card blocked", "card expired",
                     "card upgrade", "card renewal", "atm blocked", "card verification"],
        "score": 35, "label": "Card block scam"
    },
    "upi_scam": {
        "keywords": ["upi blocked", "upi limit", "upi verification", "upi update",
                     "bhim upi", "payment failed", "transaction failed"],
        "score": 25, "label": "UPI/payment scam attempt"
    },

    "otp_share": {
        "keywords": ["share otp", "send otp", "otp share", "otp forward",
                     "tell otp", "give otp", "otp bata"],
        "score": 55, "label": "OTP sharing request (critical)"
    },
    "otp_generic": {
        "keywords": ["one time password", "your otp is", "verification code",
                     "auth code", "otp is"],
        "score": 10, "label": "OTP mentioned"
    },
    "password_steal": {
        "keywords": ["share password", "send password", "login password",
                     "enter password", "password update"],
        "score": 45, "label": "Password theft attempt"
    },

    "urgency": {
        "keywords": ["immediately", "urgent", "within 24 hours", "last warning",
                     "final notice", "act now", "expire today", "expires soon",
                     "account will be closed", "action required"],
        "score": 20, "label": "Urgency pressure tactic"
    },

    "threat": {
        "keywords": ["legal action", "arrest", "police", "court notice",
                     "fraud case", "cybercrime", "penalty", "fine imposed"],
        "score": 40, "label": "Threat / legal intimidation"
    },

    "lottery": {
        "keywords": ["you have won", "congratulations you", "lucky winner",
                     "prize money", "lottery", "claim reward", "you are selected"],
        "score": 45, "label": "Lottery / prize scam"
    },

    "reward_click": {
        "keywords": ["click to claim", "claim now", "redeem now",
                     "free gift", "limited offer", "collect reward"],
        "score": 25, "label": "Fake reward / click bait"
    },

    "loan_scam": {
        "keywords": ["instant loan", "loan approved", "pre-approved loan",
                     "zero interest", "low emi", "apply now loan"],
        "score": 35, "label": "Fake loan offer"
    },

    "investment_scam": {
        "keywords": ["guaranteed return", "double your money", "high profit",
                     "daily profit", "crypto profit", "trading profit"],
        "score": 40, "label": "Investment scam"
    },

    "job_scam": {
        "keywords": ["work from home", "earn daily", "online earning",
                     "data entry job", "typing job", "like and earn"],
        "score": 30, "label": "Fake job scam"
    },

    "tax_scam": {
        "keywords": ["income tax", "tax refund", "gst notice",
                     "itr pending", "tax notice"],
        "score": 35, "label": "Tax impersonation scam"
    },

    "govt_scam": {
        "keywords": ["government scheme", "pm yojana", "aadhaar update",
                     "ration card update", "voter id update"],
        "score": 25, "label": "Government impersonation"
    },

    "tech_support": {
        "keywords": ["virus detected", "device infected", "your phone hacked",
                     "install app", "download apk", "remote access"],
        "score": 40, "label": "Tech support scam"
    },

    "suspicious_link": {
        "keywords": ["bit.ly", "tinyurl", "goo.gl", "t.co", "click here",
                     "open link", ".tk", ".xyz", ".top"],
        "score": 25, "label": "Suspicious link"
    },

    "romance_scam": {
        "keywords": ["i love you", "send money", "gift card",
                     "western union", "money transfer", "nude"],
        "score": 45, "label": "Romance scam"
    },

    "delivery_scam": {
        "keywords": ["parcel held", "package blocked", "delivery failed",
                     "customs duty", "pay customs", "shipment on hold"],
        "score": 30, "label": "Delivery scam"
    },
}

LEGITIMATE_SENDERS = [
    'sbi', 'hdfc', 'icici', 'axis', 'kotak',
    'irctc', 'uidai', 'epfo', 'nsdl',
    'amazon', 'flipkart', 'swiggy', 'zomato'
]

LINK_PATTERN = re.compile(r'https?://\S+|www\.\S+|bit\.ly|tinyurl|t\.co', re.IGNORECASE)
PHONE_IN_SMS = re.compile(r'\b[6-9]\d{9}\b')
AMOUNT_PATTERN = re.compile(r'rs\.?\s*\d+|inr\s*\d+|\d+\s*rupees', re.IGNORECASE)

CAPS_RATIO_LIMIT = 0.6


def _count_caps_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c.isupper()) / len(letters)


def analyze_sms_text(text: str) -> dict:
    text_lower = text.lower().strip()

    score = 0
    detections = []
    detail = {}

    if not text_lower:
        return {"status": "SAFE", "score": 0, "detections": [], "endee_match": None}

    # ── FIX 1: legitimate sender reduction (was missing)
    if any(sender in text_lower for sender in LEGITIMATE_SENDERS):
        score -= 15
        detections.append("Trusted sender context detected")

    matched_vectors = []

    for vector, data in SMS_SCAM_VECTORS.items():
        if any(kw in text_lower for kw in data["keywords"]):
            score += data["score"]
            detections.append(data["label"])
            matched_vectors.append(vector)

    # ── multi-pattern boost
    if len(matched_vectors) >= 4:
        score += 25
        detections.append("Multiple scam patterns detected")
    elif len(matched_vectors) >= 2:
        score += 12

    # ── FIX 2: safer link detection (no over-triggering)
    links = LINK_PATTERN.findall(text_lower)
    if links:
        score += 15
        detections.append("Suspicious link detected")
        detail["links"] = links[:3]

    # ── CAPS check (avoid OTP false positives)
    caps_ratio = _count_caps_ratio(text)
    if caps_ratio > CAPS_RATIO_LIMIT and len(text) > 25 and "otp" not in text_lower:
        score += 12
        detections.append("Excessive capital letters")

    # ── phone detection
    phones = PHONE_IN_SMS.findall(text)
    if phones:
        score += 8
        detections.append("Phone number detected")
        detail["phones"] = phones[:2]

    # ── money detection
    if AMOUNT_PATTERN.search(text):
        score += 8
        detections.append("Money reference detected")

    # ── short + link combo
    if len(text.split()) < 8 and links:
        score += 12
        detections.append("Short message with link")

    # ── Endee semantic check (FIXED threshold)
    endee_result = None
    try:
        similar = endee_semantic_search(text)
        if similar:
            top = similar[0]
            sim = top.get("score", 0)

            endee_result = {
                "similarity": round(sim * 100, 1),
                "matched_pattern": top.get("payload", {}).get("text", "")
            }

            if sim > 0.85:
                score += 30
                detections.append("Strong phishing semantic match")
            elif sim > 0.75:
                score += 20
                detections.append("Phishing-like pattern match")
            elif sim > 0.65:
                score += 10
                detections.append("Weak phishing similarity")

    except Exception as e:
        logger.warning(f"Endee SMS error: {e}")

    # ── FINAL SCORE
    final_score = max(0, min(score, 100))

    if final_score >= 55:
        status = "SCAM"
    elif final_score >= 25:
        status = "WARNING"
    else:
        status = "SAFE"

    return {
        "status": status,
        "score": final_score,
        "detections": list(dict.fromkeys(detections)),
        "endee_match": endee_result,
        "detail": detail
    }