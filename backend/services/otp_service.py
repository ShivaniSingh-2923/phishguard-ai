"""
OTP Service — secure 6-digit OTP lifecycle management.
"""

import random
import hashlib
import hmac
import os
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
OTP_EXPIRY_MINUTES  = 5
MAX_ATTEMPTS        = 3
RESEND_COOLDOWN_SEC = 30

# ── Custom Exceptions ─────────────────────────────────────────────────────────
class OTPError(Exception):
    pass

class OTPExpiredError(OTPError):
    pass

class OTPInvalidError(OTPError):
    pass

class OTPMaxAttemptsError(OTPError):
    pass

class OTPCooldownError(OTPError):
    def __init__(self, seconds_remaining: int):
        self.seconds_remaining = seconds_remaining
        super().__init__(f"Resend allowed in {seconds_remaining}s")

# ── Security: enforce secret ───────────────────────────────────────────────────
_OTP_SECRET = os.getenv("OTP_HMAC_SECRET")

if not _OTP_SECRET:
    raise RuntimeError("OTP_HMAC_SECRET must be set in environment variables")

# ── Helpers ───────────────────────────────────────────────────────────────────
def _ensure_utc(dt: datetime) -> datetime:
    """Ensure datetime is timezone-aware (UTC)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def _hash_otp(plain_otp: str) -> str:
    return hmac.new(
        _OTP_SECRET.encode(),
        plain_otp.encode(),
        hashlib.sha256
    ).hexdigest()

# ── Core functions ────────────────────────────────────────────────────────────
def generate_and_store_otp(email: str, otp_collection) -> str:
    email = email.lower().strip()
    now   = datetime.now(timezone.utc)

    existing = otp_collection.find_one({"email": email})

    if existing:
        created_at = existing.get("created_at")

        # 💥 CRITICAL FIX — handle ALL bad cases
        if not isinstance(created_at, datetime):
            logger.warning("Invalid created_at in DB → resetting OTP record")
            otp_collection.delete_one({"email": email})
            existing = None
        else:
            created_at = _ensure_utc(created_at)

            elapsed = (now - created_at).total_seconds()
            if elapsed < RESEND_COOLDOWN_SEC:
                remaining = int(RESEND_COOLDOWN_SEC - elapsed)
                raise OTPCooldownError(remaining)
            if created_at and isinstance(created_at, datetime):
                created_at = _ensure_utc(created_at)

                elapsed = (now - created_at).total_seconds()
                if elapsed < RESEND_COOLDOWN_SEC:
                    remaining = int(RESEND_COOLDOWN_SEC - elapsed)
                    raise OTPCooldownError(remaining)

    plain_otp  = str(random.SystemRandom().randint(100_000, 999_999))
    hashed_otp = _hash_otp(plain_otp)

    otp_collection.update_one(
        {"email": email},
        {"$set": {
            "email":      email,
            "otp_hash":   hashed_otp,
            "created_at": now,
            "expires_at": now + timedelta(minutes=OTP_EXPIRY_MINUTES),
            "attempts":   0,
            "verified":   False,
        }},
        upsert=True
    )

    logger.info(f"OTP generated for {email} (expires in {OTP_EXPIRY_MINUTES}m)")
    return plain_otp


from datetime import datetime, timezone
import hmac

def _ensure_utc(dt):
    """Ensure datetime is timezone-aware UTC"""
    if dt is None:
        return None
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def verify_otp(email: str, plain_otp: str, otp_collection) -> None:
    email = email.lower().strip()
    plain_otp = str(plain_otp).strip()  # ✅ FIX: avoid space issues

    now = datetime.now(timezone.utc)

    record = otp_collection.find_one({"email": email})

    # ❌ No record
    if not record:
        raise OTPInvalidError("No OTP found for this email.")

    # ❌ Corrupt record
    if "otp_hash" not in record:
        otp_collection.delete_one({"email": email})
        raise OTPInvalidError("Corrupted OTP record. Request new OTP.")

    # 🔥 SAFE EXPIRY CHECK
    expires_at = record.get("expires_at")

    if not isinstance(expires_at, datetime):
        otp_collection.delete_one({"email": email})
        raise OTPInvalidError("Invalid OTP record. Please request a new OTP.")

    expires_at = _ensure_utc(expires_at)

    # Debug (optional)
    logger.info(f"[OTP VERIFY] now={now} | expires_at={expires_at}")

    if now > expires_at:
        otp_collection.delete_one({"email": email})
        raise OTPExpiredError("OTP has expired. Please request a new OTP.")

    # 🔐 ATTEMPT LIMIT
    attempts = record.get("attempts", 0)

    if attempts >= MAX_ATTEMPTS:
        otp_collection.delete_one({"email": email})
        raise OTPMaxAttemptsError("Too many failed attempts. Please request a new OTP.")

    # 🔑 OTP CHECK
    hashed_input = _hash_otp(plain_otp)
    stored_hash = record.get("otp_hash", "")

    if not hmac.compare_digest(hashed_input, stored_hash):
        otp_collection.update_one(
            {"email": email},
            {"$inc": {"attempts": 1}}
        )

        remaining = MAX_ATTEMPTS - (attempts + 1)
        raise OTPInvalidError(f"Incorrect OTP. {remaining} attempt(s) left.")

    # ✅ SUCCESS
    otp_collection.update_one(
        {"email": email},
        {
            "$set": {
                "verified": True,
                "verified_at": now
            }
        }
    )

    logger.info(f"✅ OTP verified successfully for {email}")


def assert_otp_verified(email: str, otp_collection) -> None:
    email  = email.lower().strip()
    record = otp_collection.find_one({"email": email})

    if not record or not record.get("verified"):
        raise OTPInvalidError("OTP not verified. Complete verification first.")

    now = datetime.now(timezone.utc)

    expires_at = record.get("expires_at")
    if expires_at:
        expires_at = _ensure_utc(expires_at)

        if now > expires_at:
            otp_collection.delete_one({"email": email})
            raise OTPExpiredError("Session expired. Please restart the flow.")


def invalidate_otp(email: str, otp_collection) -> None:
    otp_collection.delete_one({"email": email.lower().strip()})
    logger.info(f"OTP invalidated for {email}")