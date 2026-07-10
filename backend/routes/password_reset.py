"""
routes/password_reset.py
─────────────────────────
Forgot-Password Flow (3 steps):
  POST /forgot-password  →  send OTP to email
  POST /verify-otp       →  validate OTP, return short-lived reset token
  POST /reset-password   →  set new password (requires reset token)

Register in app.py:
    from routes.password_reset import password_reset_bp
    app.register_blueprint(password_reset_bp)
"""

import re
import os
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta

from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash
from bson import ObjectId

# ── DB collections ────────────────────────────────────────────────────────────
from backend.config.db import users_collection, forgot_password_otp_collection as otp_collection

# ── Email service ─────────────────────────────────────────────────────────────
from backend.services.email_service import send_otp_email

logger = logging.getLogger(__name__)
password_reset_bp = Blueprint("password_reset", __name__)

# ── Constants ─────────────────────────────────────────────────────────────────
OTP_EXPIRY_MINUTES  = 5
RESET_TOKEN_MINUTES = 10
RESEND_COOLDOWN_SEC = 30
MAX_OTP_ATTEMPTS    = 3

# ── Regex ─────────────────────────────────────────────────────────────────────
EMAIL_RE = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w{2,}$')


# ─────────────────────────── PURE HELPERS ─────────────────────────────────────

def _valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email))


def _valid_password(pw: str) -> bool:
    """Min 8 chars, at least one letter and one digit."""
    return (
        len(pw) >= 8
        and any(c.isdigit() for c in pw)
        and any(c.isalpha() for c in pw)
    )


def _hash_otp(plain: str) -> str:
    """SHA-256 hash — never store or log raw OTPs."""
    return hashlib.sha256(plain.encode()).hexdigest()


def _check_otp_hash(plain: str, stored: str) -> bool:
    return hashlib.sha256(plain.encode()).hexdigest() == stored


def _create_reset_token(email: str) -> str:
    """
    Short-lived JWT with scope='password_reset'.
    Cannot be used as a normal access token.
    """
    return create_access_token(
        identity=email,
        expires_delta=timedelta(minutes=RESET_TOKEN_MINUTES),
        additional_claims={"scope": "password_reset"},
    )


# ─────────────────────────── OTP HELPERS ──────────────────────────────────────
# Inlined here so there is no missing otp_service module dependency.

def _generate_and_store_otp(email: str) -> str:
    """
    Generates a 6-digit OTP, hashes it, and upserts into otp_collection.
    Enforces 30-second resend cooldown.
    Returns the plain OTP on success.
    Raises ValueError with a user-friendly message on cooldown violation.
    """
    now = datetime.now(timezone.utc)

    # Check resend cooldown
    existing = otp_collection.find_one({"email": email})
    if existing:
        last_sent = existing.get("created_at") or existing.get("last_sent_at")
        if last_sent:
            elapsed = (now - last_sent).total_seconds()
            if elapsed < RESEND_COOLDOWN_SEC:
                wait = int(RESEND_COOLDOWN_SEC - elapsed)
                raise ValueError(f"__cooldown__{wait}")  # parsed by caller

    plain_otp = str(secrets.randbelow(900_000) + 100_000)  # always 6 digits

    otp_collection.update_one(
        {"email": email},
        {"$set": {
            "email":        email,
            "otp_hash":     _hash_otp(plain_otp),
            "expires_at":   now + timedelta(minutes=OTP_EXPIRY_MINUTES),
            "attempts":     0,
            "verified":     False,
            "used":         False,
            "created_at":   now,
            "last_sent_at": now,
        }},
        upsert=True,
    )
    return plain_otp


def _ensure_utc(dt):
    """Convert naive datetime to UTC-aware."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _verify_otp_code(email: str, plain_otp: str) -> None:
    doc = otp_collection.find_one({"email": email})

    if not doc:
        raise ValueError("__not_found__")

    if doc.get("used"):
        raise ValueError("__not_found__")

    now = datetime.now(timezone.utc)

    # ✅ FIXED HERE
    expires_at = _ensure_utc(doc.get("expires_at"))

    if expires_at and now > expires_at:
        otp_collection.delete_one({"email": email})
        raise ValueError("__expired__")

    attempts = doc.get("attempts", 0)

    if attempts >= MAX_OTP_ATTEMPTS:
        otp_collection.delete_one({"email": email})
        raise ValueError("__max_attempts__")

    if not _check_otp_hash(plain_otp, doc["otp_hash"]):
        otp_collection.update_one(
            {"email": email},
            {"$inc": {"attempts": 1}}
        )
        remaining = MAX_OTP_ATTEMPTS - attempts - 1
        raise ValueError(f"__invalid__{remaining}")

    # ✅ SUCCESS
    otp_collection.update_one(
        {"email": email},
        {"$set": {"verified": True}}
    )

def _assert_verified(email: str) -> None:
    """Raises ValueError if OTP for email is not in verified state."""
    doc = otp_collection.find_one({"email": email})
    if not doc or not doc.get("verified") or doc.get("used"):
        raise ValueError("OTP not verified. Please complete OTP verification first.")


def _invalidate_otp(email: str) -> None:
    """Mark OTP as used so it can never be replayed."""
    otp_collection.update_one(
        {"email": email},
        {"$set": {"used": True, "verified": False}},
    )


# ─────────────────────────── ROUTES ───────────────────────────────────────────

# ── STEP 1: Request OTP ───────────────────────────────────────────────────────
@password_reset_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    """
    Body:    { "email": "user@example.com" }
    Returns: 200 { message, expiry_minutes, resend_cooldown }

    Always returns a generic success message even for unknown emails
    to prevent account enumeration attacks.
    """
    data  = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({"error": "Email is required."}), 400

    if not _valid_email(email):
        return jsonify({"error": "Invalid email format."}), 400

    # Anti-enumeration: look up user silently
    user = users_collection.find_one({"email": email})
    if not user:
        logger.info("Forgot-password: unknown email — %s", email)
        # Return success anyway — never reveal whether email exists
        return jsonify({
            "message": "If that email is registered, you'll receive an OTP shortly."
        }), 200

    # Block soft-deleted accounts from resetting (they should re-register)
    if user.get("is_deleted"):
        return jsonify({
            "message": "If that email is registered, you'll receive an OTP shortly."
        }), 200

    # Generate and store OTP
    try:
        plain_otp = _generate_and_store_otp(email)
    except ValueError as e:
        msg = str(e)
        if msg.startswith("__cooldown__"):
            wait = msg.replace("__cooldown__", "")
            return jsonify({
                "error":              f"Please wait {wait} seconds before requesting a new OTP.",
                "seconds_remaining":  int(wait),
            }), 429
        logger.error("OTP generation error for %s: %s", email, e)
        return jsonify({"error": "Could not generate OTP. Please try again."}), 500

    # Send email
    sent = send_otp_email(email, plain_otp, expiry_minutes=OTP_EXPIRY_MINUTES)
    if not sent:
        _invalidate_otp(email)
        return jsonify({"error": "Failed to send OTP email. Please try again later."}), 503

    logger.info("Forgot-password OTP sent to %s", email)
    return jsonify({
        "message":         "OTP sent! Check your inbox.",
        "expiry_minutes":  OTP_EXPIRY_MINUTES,
        "resend_cooldown": RESEND_COOLDOWN_SEC,
    }), 200


# ── STEP 2: Verify OTP ────────────────────────────────────────────────────────
@password_reset_bp.route("/verify-otp", methods=["POST"])
def verify_otp_route():
    """
    Body:    { "email": "user@example.com", "otp": "123456" }
    Returns: 200 { message, reset_token, reset_token_expires_in }
    """
    data  = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    otp   = data.get("otp",   "").strip()

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required."}), 400

    if not _valid_email(email):
        return jsonify({"error": "Invalid email format."}), 400

    if not otp.isdigit() or len(otp) != 6:
        return jsonify({"error": "OTP must be a 6-digit number."}), 400

    try:
        _verify_otp_code(email, otp)
    except ValueError as e:
        msg = str(e)
        if "__not_found__" in msg:
            return jsonify({"error": "No active OTP found. Please request a new one.", "code": "OTP_NOT_FOUND"}), 400
        if "__expired__" in msg:
            return jsonify({"error": "OTP has expired. Please request a new one.",     "code": "OTP_EXPIRED"}),   410
        if "__max_attempts__" in msg:
            return jsonify({"error": "Too many wrong attempts. Please request a new OTP.", "code": "OTP_MAX_ATTEMPTS"}), 429
        if "__invalid__" in msg:
            remaining = msg.replace("__invalid__", "")
            return jsonify({"error": f"Incorrect OTP. {remaining} attempt(s) remaining.", "code": "OTP_INVALID"}), 400
        return jsonify({"error": "OTP verification failed.", "code": "OTP_ERROR"}), 400

    reset_token = _create_reset_token(email)
    logger.info("OTP verified; reset token issued for %s", email)

    return jsonify({
        "message":                "OTP verified! You may now reset your password.",
        "reset_token":            reset_token,
        "reset_token_expires_in": RESET_TOKEN_MINUTES * 60,
    }), 200


# ── STEP 3: Set new password ──────────────────────────────────────────────────
@password_reset_bp.route("/reset-password", methods=["POST"])
@jwt_required()
def reset_password():
    """
    Headers: Authorization: Bearer <reset_token>
    Body:    { "new_password": "...", "confirm_password": "..." }

    The reset_token JWT must carry scope='password_reset' —
    prevents a normal access token being used here.
    """
    # Validate JWT scope
    claims = get_jwt()
    if claims.get("scope") != "password_reset":
        return jsonify({"error": "Invalid token type for password reset."}), 403

    email = get_jwt_identity().strip().lower()

    data             = request.get_json(silent=True) or {}
    new_password     = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if not new_password or not confirm_password:
        return jsonify({"error": "new_password and confirm_password are required."}), 400

    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match."}), 400

    if not _valid_password(new_password):
        return jsonify({
            "error": "Password must be at least 8 characters with at least one letter and one number."
        }), 400

    # Confirm OTP step was completed (prevents step-skipping)
    try:
        _assert_verified(email)
    except ValueError as e:
        return jsonify({"error": str(e), "code": "OTP_NOT_VERIFIED"}), 403

    # Update password
    hashed = generate_password_hash(new_password)
    result = users_collection.update_one(
        {"email": email},
        {"$set": {
            "password":            hashed,
            "password_changed_at": datetime.now(timezone.utc),
        }}
    )

    if result.matched_count == 0:
        return jsonify({"error": "User not found."}), 404

    # Consume OTP — can never be replayed
    _invalidate_otp(email)

    logger.info("Password reset successfully for %s", email)
    return jsonify({"message": "Password reset successful! You can now log in."}), 200