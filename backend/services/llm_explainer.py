from __future__ import annotations
import os
import logging
from typing import List, Optional
from groq import Groq
from dotenv import load_dotenv



# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

# Singleton client
_CLIENT = None

def _get_client():
    global _CLIENT
    if _CLIENT is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            logger.warning("GROQ_API_KEY not found in environment")
            return None
        _CLIENT = Groq(api_key=api_key)
    return _CLIENT


# 🔥 Universal Cybersecurity Prompt
_SYSTEM_PROMPT = """
You are an expert cybersecurity assistant for a scam detection system.

Your job is to explain scan results clearly to a non-technical user.

Guidelines:
- Write 2–4 short paragraphs (no bullet points, no markdown).
- Start with a clear verdict (SAFE, SUSPICIOUS, or SCAM).
- Explain detected risks in simple language.
- Connect multiple warning signs logically.
- Mention any positive/safe signals if present.
- Adapt explanation based on scan type:
    • URL → phishing links, fake domains
    • Voice → scam calls, impersonation, urgency tactics
    • OCR/Image → fake documents, misleading text
    • SMS → spam, malicious links, threats
    • Phone → spam reports, unknown caller risks
- Do NOT repeat the input more than once.
- Keep tone calm, helpful, and realistic.
- End with ONE clear safety recommendation.

Avoid:
- Technical jargon
- Repetition
- Over-dramatic tone
""".strip()


def generate_llm_explanation(
    input_data: str,
    reasons: List[str],
    score: int | float,
    confidence: float,
    verdict: str = "",
    scan_type: str = "url",
) -> Optional[str]:
    """
    Generate user-friendly explanation for scan results.

    Args:
        input_data: URL / text / number / file label
        reasons: list of detected risk signals
        score: risk score (0–100)
        confidence: ML confidence %
        verdict: optional (SAFE / WARNING / SCAM)
        scan_type: url / voice / ocr / sms / phone

    Returns:
        explanation string or None
    """

    if not input_data:
        return None

    # Format reasons
    reasons_text = "\n".join(f"- {r}" for r in reasons) if reasons else "- No major risk indicators detected."

    # Decide verdict if not provided
    if not verdict:
        if score >= 70:
            verdict = "SCAM"
        elif score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

    prompt = f"""
Scan Type: {scan_type.upper()}

Input analysed: {input_data}

Risk score: {int(score)}/100
Verdict: {verdict}
ML confidence: {round(float(confidence), 1)}%

Detected signals:
{reasons_text}

Explain this result for a normal user based on the scan type.
""".strip()

    try:
        client = _get_client()
        if client is None:
            return None

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            max_tokens=400,
            temperature=0.4,
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        logger.warning(f"Groq LLM error: {e}")
        return None