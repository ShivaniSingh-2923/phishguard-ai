"""
routes/profile_security.py
──────────────────────────
ADD-ONLY — does not touch any existing route.

Register in app.py with:
    from routes.profile_security import profile_security_bp
    app.register_blueprint(profile_security_bp)

New endpoints:
  POST   /auth/password/verify-current   Step 1 – verify current pw, send OTP
  POST   /auth/password/resend-otp       Resend with 30-sec cooldown
  POST   /auth/password/verify-otp       Step 2 – check 6-digit OTP
  POST   /auth/password/set-new          Step 3 – commit new password
  DELETE /auth/account/delete            Soft-delete account
"""

import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta

import bcrypt
from bson import ObjectId
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

# ── Shared DB handles from your existing config ───────────────────────────────
from backend.config.db import users_collection, change_password_otp_collection as otp_collection
from backend.services.email_service import send_change_password_otp

logger = logging.getLogger(__name__)
profile_security_bp = Blueprint("profile_security", __name__)


# ──────────────────────────── PURE HELPERS ────────────────────────────────────

def _hash_otp(plain: str) -> str:
    """SHA-256 hash of OTP. We never store or log the raw value."""
    return hashlib.sha256(plain.encode()).hexdigest()


def _check_otp(plain: str, stored: str) -> bool:
    return hashlib.sha256(plain.encode()).hexdigest() == stored


def _password_policy(pw: str) -> tuple[bool, str]:
    """Returns (ok, error_msg). Matches the UI strength-meter rules."""
    if len(pw) < 8:
        return False, "Password must be at least 8 characters."
    if not any(c.isupper() for c in pw):
        return False, "Must contain at least one uppercase letter."
    if not any(c.isdigit() for c in pw):
        return False, "Must contain at least one number."
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pw):
        return False, "Must contain at least one special character."
    return True, ""


def _get_user(user_id: str) -> dict | None:
    return users_collection.find_one({"_id": ObjectId(user_id)})


def _verify_password(plain: str, stored_hash: str) -> bool:
    """
    Works with BOTH werkzeug hashes (existing users) and raw bcrypt hashes.
    This ensures backward-compatibility — existing passwords are NOT invalidated.
    """
    if stored_hash.startswith(("pbkdf2", "scrypt")):
        from werkzeug.security import check_password_hash
        return check_password_hash(stored_hash, plain)
    try:
        return bcrypt.checkpw(plain.encode(), stored_hash.encode())
    except Exception:
        return False


def _make_aware(dt: datetime | None) -> datetime | None:
    """
    PyMongo strips tzinfo when reading datetimes back from MongoDB.
    This reattaches UTC so comparisons with datetime.now(timezone.utc) never crash.
    Safe to call on already-aware datetimes — it's a no-op in that case.
    """
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ──────────────────── STEP 1 — verify current password ───────────────────────

@profile_security_bp.route("/auth/password/verify-current", methods=["POST"])
@jwt_required()
def verify_current_password():
    """
    Body:    { "current_password": "..." }
    Success: 200 { message, otp_expires_in: 300 }

    Guards:
      • Account not soft-deleted
      • 15-day cooldown since last change
      • Current password correct
    On success → generates OTP, hashes it, persists in otp_collection, emails user.
    """
    user_id = get_jwt_identity()
    data    = request.get_json(silent=True) or {}
    cur_pw  = data.get("current_password", "").strip()

    if not cur_pw:
        return jsonify({"error": "Current password is required."}), 400

    user = _get_user(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404
    if user.get("is_deleted"):
        return jsonify({"error": "Account no longer exists."}), 403

    # ── 15-day gate ───────────────────────────────────────────────────────────
    last = _make_aware(user.get("password_changed_at"))
    if last:
        elapsed_days = (datetime.now(timezone.utc) - last).days
        if elapsed_days < 15:
            remaining = 15 - elapsed_days
            return jsonify({
                "error": (
                    f"Password changed {elapsed_days} day(s) ago. "
                    f"You may change it again in {remaining} day(s)."
                ),
                "days_remaining": remaining,
            }), 429

    # ── Verify current password ───────────────────────────────────────────────
    if not _verify_password(cur_pw, user.get("password", "")):
        logger.warning("Bad current-password attempt — user %s", user_id)
        return jsonify({"error": "Current password is incorrect."}), 401

    # ── Generate + store OTP ──────────────────────────────────────────────────
    otp_plain = str(secrets.randbelow(900_000) + 100_000)   # 6-digit: 100000–999999
    now       = datetime.now(timezone.utc)

    otp_collection.update_one(
        {"user_id": user_id},
        {"$set": {
            "user_id":      user_id,
            "otp_hash":     _hash_otp(otp_plain),
            "expires_at":   now + timedelta(minutes=5),
            "attempts":     0,
            "verified":     False,
            "used":         False,
            "last_sent_at": now,
        }},
        upsert=True,
    )

    # ── Email ─────────────────────────────────────────────────────────────────
    try:
        send_change_password_otp(user["email"], user.get("name", "User"), otp_plain)
    except Exception as exc:
        logger.error("OTP email failed for user %s: %s", user_id, exc)
        return jsonify({"error": "Could not send OTP email. Please try again."}), 500

    email    = user["email"]
    masked   = email[:3] + "***@" + email.split("@")[1]
    return jsonify({"message": f"OTP sent to {masked}.", "otp_expires_in": 300}), 200


# ──────────────────────────── RESEND OTP ─────────────────────────────────────

@profile_security_bp.route("/auth/password/resend-otp", methods=["POST"])
@jwt_required()
def resend_otp():
    """30-second server-side cooldown on resends."""
    user_id = get_jwt_identity()
    user    = _get_user(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    doc = otp_collection.find_one({"user_id": user_id})
    if doc:
        last_sent = _make_aware(doc.get("last_sent_at"))
        if last_sent:
            elapsed = (datetime.now(timezone.utc) - last_sent).total_seconds()
            if elapsed < 30:
                wait = int(30 - elapsed)
                return jsonify({
                    "error":              f"Wait {wait}s before requesting another OTP.",
                    "cooldown_remaining": wait,
                }), 429

    otp_plain = str(secrets.randbelow(900_000) + 100_000)
    now       = datetime.now(timezone.utc)

    otp_collection.update_one(
        {"user_id": user_id},
        {"$set": {
            "otp_hash":     _hash_otp(otp_plain),
            "expires_at":   now + timedelta(minutes=5),
            "attempts":     0,
            "verified":     False,
            "used":         False,
            "last_sent_at": now,
        }},
        upsert=True,
    )

    try:
        send_change_password_otp(user["email"], user.get("name", "User"), otp_plain)
    except Exception as exc:
        logger.error("Resend OTP email failed: %s", exc)
        return jsonify({"error": "Could not resend OTP. Try again."}), 500

    return jsonify({"message": "New OTP sent successfully."}), 200


# ──────────────────────── STEP 2 — verify OTP ────────────────────────────────

@profile_security_bp.route("/auth/password/verify-otp", methods=["POST"])
@jwt_required()
def verify_otp():
    """
    Body:  { "otp": "123456" }
    Max 3 wrong attempts → OTP document deleted, user must restart.
    """
    user_id = get_jwt_identity()
    data    = request.get_json(silent=True) or {}
    otp_in  = data.get("otp", "").strip()

    if not otp_in or not otp_in.isdigit() or len(otp_in) != 6:
        return jsonify({"error": "Please enter a valid 6-digit OTP."}), 400

    doc = otp_collection.find_one({"user_id": user_id})

    if not doc:
        return jsonify({"error": "No active OTP. Please request one."}), 400
    if doc.get("used"):
        return jsonify({"error": "OTP already used. Request a new one."}), 400
    expires_at = _make_aware(doc.get("expires_at"))
    if not expires_at or datetime.now(timezone.utc) > expires_at:
        return jsonify({"error": "OTP has expired. Request a new one."}), 400

    attempts = doc.get("attempts", 0)
    if attempts >= 3:
        otp_collection.delete_one({"user_id": user_id})
        return jsonify({
            "error": "Too many wrong attempts. Please restart the process."
        }), 429

    if not _check_otp(otp_in, doc["otp_hash"]):
        otp_collection.update_one({"user_id": user_id}, {"$inc": {"attempts": 1}})
        left = 2 - attempts
        return jsonify({"error": f"Incorrect OTP. {left} attempt(s) left."}), 401

    # Correct — mark verified so Step 3 can proceed
    otp_collection.update_one(
        {"user_id": user_id},
        {"$set": {"verified": True}},
    )
    return jsonify({"message": "OTP verified. Set your new password."}), 200


# ──────────────────────── STEP 3 — set new password ──────────────────────────

@profile_security_bp.route("/auth/password/set-new", methods=["POST"])
@jwt_required()
def set_new_password():
    """
    Body:  { "new_password": "...", "confirm_password": "..." }
    Requires OTP to have been verified (prevents step-skipping attacks).
    """
    user_id = get_jwt_identity()
    data    = request.get_json(silent=True) or {}
    new_pw  = data.get("new_password", "")
    confirm = data.get("confirm_password", "")

    if not new_pw or not confirm:
        return jsonify({"error": "Both password fields are required."}), 400
    if new_pw != confirm:
        return jsonify({"error": "Passwords do not match."}), 400

    ok, msg = _password_policy(new_pw)
    if not ok:
        return jsonify({"error": msg}), 400

    # Prevent step-skipping
    doc = otp_collection.find_one({"user_id": user_id})
    if not doc or not doc.get("verified"):
        return jsonify({"error": "OTP verification required first."}), 403

    hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {
            "password":            hashed,
            "password_changed_at": datetime.now(timezone.utc),
        }},
    )

    # Consume OTP — can never be replayed
    otp_collection.update_one(
        {"user_id": user_id},
        {"$set": {"used": True, "verified": False}},
    )

    logger.info("Password changed successfully — user %s", user_id)
    return jsonify({"message": "Password changed! Please log in again."}), 200


# ──────────────────────── SOFT-DELETE ACCOUNT ────────────────────────────────

@profile_security_bp.route("/auth/account/delete", methods=["DELETE"])
@jwt_required()
def delete_account():
    """
    Soft-delete strategy (recommended over hard-delete):
    ──────────────────────────────────────────────────────
    We set is_deleted=True and clear all PII (name, email, password) from the
    user document. We do NOT delete the user _id row or any scan/report records.

    Why?
      • Scan history references user_id for ML training & abuse forensics.
      • GDPR Art. 17 allows retaining anonymised/aggregate data even after an
        erasure request — only identifiable personal data must be removed.
      • Real-world examples: GitHub keeps commit history attributed to a ghost
        "Deleted User"; Slack retains messages and replaces display name.

    After deletion:
      • Login returns 403 (blocked in /auth/login — see app.py change below).
      • Re-registering with the same email is allowed (email is now cleared).

    Body: { "password": "current-password" }   ← re-auth before destructive op
    """
    user_id    = get_jwt_identity()
    data       = request.get_json(silent=True) or {}
    confirm_pw = data.get("password", "")

    if not confirm_pw:
        return jsonify({"error": "Password confirmation is required."}), 400

    user = _get_user(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404
    if user.get("is_deleted"):
        return jsonify({"error": "Account already deleted."}), 400

    if not _verify_password(confirm_pw, user.get("password", "")):
        return jsonify({"error": "Incorrect password."}), 401

    now = datetime.now(timezone.utc)
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "is_deleted": True,
                "deleted_at": now,
                # Anonymise PII — _id kept for scan FK integrity
                "name":       "[Deleted User]",
                "email":      f"deleted_{user_id}@removed.invalid",
                "password":   "",
            },
            "$unset": {"phone": ""},
        },
    )

    otp_collection.delete_many({"user_id": user_id})
    logger.info("Soft-deleted account — user %s at %s", user_id, now)

    return jsonify({
        "message": "Account deleted. Your personal data has been removed."
    }), 200