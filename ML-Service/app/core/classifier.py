"""
Threat classification logic - maps probability → threat level → action.
"""
from app.core.config import settings


def classify(probability: float) -> tuple[str, str]:
    """
    Maps threat probability to (threatLevel, action).

    Thresholds configured in settings:
      >= BLOCK_THRESHOLD   (0.80) → CRITICAL THREAT / BLOCK
      >= CAPTCHA_THRESHOLD (0.60) → HIGH THREAT     / CAPTCHA
      >= MONITOR_THRESHOLD (0.40) → MEDIUM THREAT   / MONITOR
      else                        → LOW THREAT      / ALLOW
    """
    if probability >= settings.BLOCK_THRESHOLD:
        return "CRITICAL THREAT", "BLOCK"
    elif probability >= settings.CAPTCHA_THRESHOLD:
        return "HIGH THREAT", "CAPTCHA"
    elif probability >= settings.MONITOR_THRESHOLD:
        return "MEDIUM THREAT", "MONITOR"
    else:
        return "LOW THREAT", "ALLOW"