"""
services/email_service.py
──────────────────────────
Single email service for ALL transactional emails in PhishGuard.
"""

import os
import logging
import ssl
import smtplib   # ✅ FIXED (MISSING IMPORT)
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

# ✅ LOAD ENV FILE
load_dotenv()

logger = logging.getLogger(__name__)

# ── SMTP config ──────────────────────────────────────────────────────────────
MAIL_SERVER  = os.getenv("MAIL_SERVER",  "smtp.gmail.com")
MAIL_PORT    = int(os.getenv("MAIL_PORT", "587"))
MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
MAIL_USER    = os.getenv("MAIL_USERNAME", "")
MAIL_PASS    = os.getenv("MAIL_PASSWORD", "")

MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "PhishGuard")
MAIL_FROM      = formataddr((MAIL_FROM_NAME, MAIL_USER))

APP_NAME     = os.getenv("APP_NAME", "PhishGuard")


# ─────────────────────────── SHARED SMTP SENDER ───────────────────────────────

def _send(to_email: str, subject: str, html: str, plain: str) -> bool:

    if not MAIL_USER or not MAIL_PASS:
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
        context = ssl.create_default_context()

        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=15) as server:
            server.ehlo()

            if MAIL_USE_TLS:
                server.starttls(context=context)
                server.ehlo()

            # 🔍 Debug log (helps your current issue)
            logger.info(f"Logging in as {MAIL_USER}")

            server.login(MAIL_USER, MAIL_PASS)

            # ✅ FIXED (use proper FROM)
            server.sendmail(msg["From"], to_email, msg.as_string())

        logger.info(f"Email sent → {to_email} | {subject}")
        return True

    except smtplib.SMTPAuthenticationError as e:
        logger.error("❌ SMTP auth failed — INVALID Gmail App Password")
        logger.error(str(e))

    except smtplib.SMTPConnectError as e:
        logger.error("❌ SMTP connection failed (network/firewall issue)")
        logger.error(str(e))

    except smtplib.SMTPException as e:
        logger.error(f"❌ SMTP error → {to_email}: {e}")

    except Exception as e:
        logger.error(f"❌ Unexpected email error: {e}")

    return False


# ─────────────────────────── SHARED HTML HELPERS ─────────────────────────────

def _digit_boxes(otp: str, bg: str, fg: str) -> str:
    return "".join(
        f'<span style="display:inline-block;width:48px;height:56px;line-height:56px;'
        f'text-align:center;font-size:28px;font-weight:700;'
        f'background:{bg};color:{fg};border-radius:10px;margin:0 4px;'
        f'font-family:Courier New,monospace;">{d}</span>'
        for d in otp
    )


def _wrap(header: str, body: str, dark: bool) -> str:
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

def send_otp_email(to_email: str, otp: str, expiry_minutes: int = 5) -> bool:

    subject = f"🔐 Your {APP_NAME} Verification Code: {otp}"
    boxes   = _digit_boxes(otp, bg="#0f172a", fg="#38bdf8")

    header = f"""<tr><td style="background:#0ea5e9;padding:36px 40px;text-align:center;">
    <h1 style="margin:0;color:#fff;">🛡️ {APP_NAME}</h1></td></tr>"""

    body = f"""<tr><td style="padding:40px;">
    <p>Your OTP is:</p><div>{boxes}</div></td></tr>"""

    plain = f"{APP_NAME} OTP: {otp}"

    return _send(to_email, subject, _wrap(header, body, True), plain)


# ══════════════════════════════════════════════════════════════════════════════

def send_change_password_otp(to_email: str, user_name: str, otp: str) -> bool:

    subject = f"Your {APP_NAME} Password Change OTP"
    boxes   = _digit_boxes(otp, bg="#eef2ff", fg="#3730a3")

    header = f"""<tr><td style="padding:30px;text-align:center;">
    🛡️ {APP_NAME}</td></tr>"""

    body = f"""<tr><td style="padding:40px;">
    Hi {user_name}, your OTP is:<br>{boxes}</td></tr>"""

    plain = f"Hi {user_name}, OTP: {otp}"

    return _send(to_email, subject, _wrap(header, body, False), plain)