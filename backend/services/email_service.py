"""
services/email_service.py
──────────────────────────
Single email service for ALL transactional emails in PhishGuard.
Uses raw smtplib — no Flask-Mail dependency needed.

Handles:
  1. send_otp_email()            → Forgot-password OTP  (existing, signature UNCHANGED)
  2. send_change_password_otp()  → Change-password OTP  (new, profile security)

Config via .env:
  MAIL_SERVER          smtp.gmail.com
  MAIL_PORT            587
  MAIL_USE_TLS         true
  MAIL_USERNAME        you@gmail.com
  MAIL_PASSWORD        your_16_char_app_password
  MAIL_DEFAULT_SENDER  PhishGuard <you@gmail.com>
  APP_NAME             PhishGuard
"""

import os
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

# ── SMTP config (read once at import time) ────────────────────────────────────
MAIL_SERVER  = os.getenv("MAIL_SERVER",  "smtp.gmail.com")
MAIL_PORT    = int(os.getenv("MAIL_PORT", "587"))
MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
MAIL_USER    = os.getenv("MAIL_USERNAME", "")
MAIL_PASS    = os.getenv("MAIL_PASSWORD", "")
MAIL_FROM    = os.getenv("MAIL_DEFAULT_SENDER", f"PhishGuard <{MAIL_USER}>")
APP_NAME     = os.getenv("APP_NAME", "PhishGuard")


# ─────────────────────────── SHARED SMTP SENDER ───────────────────────────────

def _send(to_email: str, subject: str, html: str, plain: str) -> bool:
    """
    Core SMTP send used by ALL email functions in this file.
    Returns True on success, False on failure — never raises.
    In dev mode (no credentials set), prints to console instead of sending.
    """
    if not MAIL_USER or not MAIL_PASS:
        # Dev mode: no email sent, content printed to terminal
        logger.warning(f"[DEV MODE] Email to {to_email} | Subject: {subject}")
        logger.warning(f"[DEV MODE] Body:\n{plain}")
        return True

    msg            = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = MAIL_FROM
    msg["To"]      = to_email
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html,  "html"))

    try:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=10) as server:
            if MAIL_USE_TLS:
                server.starttls()
            server.login(MAIL_USER, MAIL_PASS)
            server.sendmail(MAIL_FROM, to_email, msg.as_string())
        logger.info(f"Email sent → {to_email} | {subject}")
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP auth failed — check MAIL_USERNAME / MAIL_PASSWORD in .env")
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error → {to_email}: {e}")
    except Exception as e:
        logger.error(f"Unexpected email error: {e}")
    return False


# ─────────────────────────── SHARED HTML HELPERS ─────────────────────────────

def _digit_boxes(otp: str, bg: str, fg: str) -> str:
    """Renders each OTP digit as an individual styled box."""
    return "".join(
        f'<span style="display:inline-block;width:48px;height:56px;line-height:56px;'
        f'text-align:center;font-size:28px;font-weight:700;'
        f'background:{bg};color:{fg};border-radius:10px;margin:0 4px;'
        f'font-family:Courier New,monospace;">{d}</span>'
        for d in otp
    )


def _wrap(header: str, body: str, dark: bool) -> str:
    """Shared outer HTML shell. dark=True for forgot-pw, dark=False for change-pw."""
    outer   = "#0f172a" if dark else "#f1f5f9"
    card    = "#1e293b" if dark else "#ffffff"
    foot_bg = "#0f172a" if dark else "#f9fafb"
    foot_tx = "#334155" if dark else "#9ca3af"
    divider = "#1e293b" if dark else "#f3f4f6"

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/></head>
<body style="margin:0;padding:0;background:{outer};
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 0;">
  <tr><td align="center">
    <table width="560" cellpadding="0" cellspacing="0"
      style="background:{card};border-radius:20px;overflow:hidden;
             box-shadow:0 8px 40px rgba(0,0,0,0.12);">
      {header}
      {body}
      <tr>
        <td style="background:{foot_bg};padding:22px 40px;
                   border-top:1px solid {divider};text-align:center;">
          <p style="margin:0;font-size:12px;color:{foot_tx};line-height:1.6;">
            © 2025 {APP_NAME} · Automated message, do not reply.
          </p>
        </td>
      </tr>
    </table>
  </td></tr>
</table>
</body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 1 — Forgot Password OTP
# Called by: routes/password_reset.py
# Signature: send_otp_email(to_email, otp, expiry_minutes=5)  ← UNCHANGED
# Theme: dark (matches your original design exactly)
# ══════════════════════════════════════════════════════════════════════════════

def send_otp_email(to_email: str, otp: str, expiry_minutes: int = 5) -> bool:
    """
    Forgot-password OTP email.
    Existing callers need zero changes — signature is identical to before.
    """
    subject = f"🔐 Your {APP_NAME} Verification Code: {otp}"
    boxes   = _digit_boxes(otp, bg="#0f172a", fg="#38bdf8")

    header = f"""
    <tr>
      <td style="background:linear-gradient(135deg,#0ea5e9 0%,#6366f1 100%);
                 padding:36px 40px;text-align:center;">
        <h1 style="margin:0;color:#fff;font-size:26px;font-weight:800;">
          🛡️ {APP_NAME}
        </h1>
        <p style="margin:6px 0 0;color:rgba(255,255,255,0.85);font-size:14px;">
          AI-Powered Scam Protection
        </p>
      </td>
    </tr>"""

    body = f"""
    <tr>
      <td style="padding:40px 40px 32px;">
        <h2 style="margin:0 0 12px;color:#f1f5f9;font-size:22px;font-weight:700;">
          Password Reset Request
        </h2>
        <p style="margin:0 0 28px;color:#94a3b8;font-size:15px;line-height:1.6;">
          We received a request to reset your {APP_NAME} password.
          Use the code below — expires in
          <strong style="color:#38bdf8;">{expiry_minutes} minutes</strong>.
        </p>
        <div style="text-align:center;margin:32px 0;">
          <div style="background:#0f172a;border-radius:14px;
                      padding:24px 20px;display:inline-block;">
            {boxes}
          </div>
          <p style="margin:14px 0 0;color:#64748b;font-size:12px;
                    letter-spacing:1px;text-transform:uppercase;">
            One-Time Password · {expiry_minutes}-minute expiry
          </p>
        </div>
        <div style="background:#1a2744;border:1px solid #1e3a5f;
                    border-radius:10px;padding:16px 20px;">
          <p style="margin:0;color:#93c5fd;font-size:13px;line-height:1.6;">
            ⚠️ <strong>Never share this code.</strong>
            {APP_NAME} staff will never ask for it.
            If you didn't request this, safely ignore this email.
          </p>
        </div>
      </td>
    </tr>"""

    plain = (
        f"{APP_NAME} — Password Reset OTP\n\n"
        f"Your one-time password is: {otp}\n\n"
        f"Expires in {expiry_minutes} minutes. Do NOT share it.\n\n"
        f"If you didn't request this, ignore this email."
    )

    return _send(to_email, subject, _wrap(header, body, dark=True), plain)


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 2 — Change Password OTP  (new)
# Called by: routes/profile_security.py
# Signature: send_change_password_otp(to_email, user_name, otp)
# Theme: light — visually distinct so users can tell the two emails apart
# ══════════════════════════════════════════════════════════════════════════════

def send_change_password_otp(to_email: str, user_name: str, otp: str) -> bool:
    """
    Change-password OTP email for logged-in users.
    Different subject line and light theme so it's never confused
    with the forgot-password email.
    """
    subject = f"Your {APP_NAME} Password Change OTP"
    boxes   = _digit_boxes(otp, bg="#eef2ff", fg="#3730a3")

    header = f"""
    <tr>
      <td style="background:linear-gradient(135deg,#3730a3 0%,#6d28d9 100%);
                 padding:30px 40px;text-align:center;">
        <span style="font-size:22px;">🛡️</span>
        <span style="display:inline-block;margin-left:8px;color:#fff;
                     font-size:20px;font-weight:800;vertical-align:middle;">
          {APP_NAME}
        </span>
      </td>
    </tr>"""

    body = f"""
    <tr>
      <td style="padding:40px 40px 32px;">
        <h2 style="margin:0 0 8px;color:#111827;font-size:21px;font-weight:700;">
          Password Change Request
        </h2>
        <p style="margin:0 0 28px;color:#6b7280;font-size:14px;line-height:1.7;">
          Hi <strong style="color:#374151;">{user_name}</strong>, use the one-time
          code below to continue changing your {APP_NAME} password.
        </p>
        <div style="background:#f5f7ff;border:2px dashed #c7d2fe;border-radius:16px;
                    padding:28px 24px;text-align:center;margin-bottom:28px;">
          <p style="margin:0 0 18px;font-size:11px;font-weight:700;
                     text-transform:uppercase;letter-spacing:2px;color:#9ca3af;">
            One-Time Password
          </p>
          {boxes}
          <p style="margin:18px 0 0;font-size:13px;color:#6b7280;">
            ⏱ Expires in <strong>5 minutes</strong> · Single use only
          </p>
        </div>
        <div style="background:#fff7ed;border-left:4px solid #f97316;
                    border-radius:8px;padding:14px 16px;">
          <p style="margin:0;font-size:13px;color:#92400e;line-height:1.5;">
            <strong>⚠ Security tip:</strong> {APP_NAME} will never ask for this
            code via phone or chat. If you didn't request this change,
            your account is unchanged — safely ignore this email.
          </p>
        </div>
      </td>
    </tr>"""

    plain = (
        f"Hi {user_name},\n\n"
        f"Your {APP_NAME} password change OTP is: {otp}\n\n"
        f"Expires in 5 minutes. Single use only.\n\n"
        f"If you didn't request this, your account is unchanged.\n\n"
        f"— {APP_NAME} Security Team"
    )

    return _send(to_email, subject, _wrap(header, body, dark=False), plain)