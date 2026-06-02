"""
OTP Service — secure 6-digit OTP lifecycle management.

Flow:
  1. generate_and_store_otp(email)  →  plain OTP (send via email)
  2. verify_otp(email, plain_otp)   →  True / raises OTPError
  3. invalidate_otp(email)          →  cleanup after reset
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
    """Base OTP error."""

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

# ── Hash helper ───────────────────────────────────────────────────────────────
_OTP_SECRET = os.getenv("OTP_HMAC_SECRET", "change-this-secret-in-production")

def _hash_otp(plain_otp: str) -> str:
    """HMAC-SHA256 hash so raw OTPs are never stored."""
    return hmac.new(
        _OTP_SECRET.encode(),
        plain_otp.encode(),
        hashlib.sha256
    ).hexdigest()

# ── Core functions ────────────────────────────────────────────────────────────
def generate_and_store_otp(email: str, otp_collection) -> str:
    """
    Generate a 6-digit OTP, hash it, and upsert into MongoDB.
    Returns the PLAIN OTP (so it can be emailed — never logged or stored).

    Enforces resend cooldown: raises OTPCooldownError if called too soon.
    """
    email = email.lower().strip()
    now   = datetime.now(timezone.utc)

    # Check cooldown — did we send one recently?
    existing = otp_collection.find_one({"email": email})
    if existing:
        created_at = existing.get("created_at")
        if created_at and isinstance(created_at, datetime):
            # Make timezone-aware if needed
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
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
    return plain_otp   # ← send this via email, never store/log it


def verify_otp(email: str, plain_otp: str, otp_collection) -> None:
    """
    Verify OTP. Raises a specific OTPError subclass on failure.
    On success, marks the record as verified (but does NOT delete it yet —
    deletion happens after the password is actually reset).
    """
    email = email.lower().strip()
    now   = datetime.now(timezone.utc)

    record = otp_collection.find_one({"email": email})

    if not record:
        raise OTPInvalidError("No OTP found for this email.")

    # Check expiry
    expires_at = record.get("expires_at")
    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            otp_collection.delete_one({"email": email})
            raise OTPExpiredError("OTP has expired. Please request a new one.")

    # Check attempt limit
    attempts = record.get("attempts", 0)
    if attempts >= MAX_ATTEMPTS:
        otp_collection.delete_one({"email": email})
        raise OTPMaxAttemptsError("Too many failed attempts. Please request a new OTP.")

    # Compare hash
    if not hmac.compare_digest(_hash_otp(plain_otp), record["otp_hash"]):
        otp_collection.update_one(
            {"email": email},
            {"$inc": {"attempts": 1}}
        )
        remaining = MAX_ATTEMPTS - (attempts + 1)
        raise OTPInvalidError(f"Incorrect OTP. {remaining} attempt(s) left.")

    # ✅ Correct — mark verified
    otp_collection.update_one(
        {"email": email},
        {"$set": {"verified": True}}
    )
    logger.info(f"OTP verified successfully for {email}")


def assert_otp_verified(email: str, otp_collection) -> None:
    """
    Called during /reset-password to confirm the user actually verified their OTP
    before allowing a password change (prevents skipping the OTP step).
    """
    email  = email.lower().strip()
    record = otp_collection.find_one({"email": email})

    if not record or not record.get("verified"):
        raise OTPInvalidError("OTP not verified. Complete verification first.")

    # Also check expiry hasn't slipped by
    now        = datetime.now(timezone.utc)
    expires_at = record.get("expires_at")
    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            otp_collection.delete_one({"email": email})
            raise OTPExpiredError("Session expired. Please restart the forgot-password flow.")


def invalidate_otp(email: str, otp_collection) -> None:
    """Remove the OTP record after a successful password reset."""
    otp_collection.delete_one({"email": email.lower().strip()})
    logger.info(f"OTP invalidated for {email}")