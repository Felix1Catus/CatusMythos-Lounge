"""Safe evidence helpers shared by API-breaker scripts."""

import json
import re


SENSITIVE_RESPONSE_KEY = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"authorization|cookie|credit.?card|cc.?number|ssn|social.?security|"
    r"email|phone|mobile|address|date.?of.?birth|\bdob\b|"
    r"first.?name|last.?name|full.?name|display.?name|username|"
    r"(?:^|[_-])name(?:$|[_-]))",
    re.IGNORECASE,
)
INLINE_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
INLINE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
INLINE_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|cookie)"
    r"\b[\"']?\s*[:=]\s*[\"']?(?:Bearer\s+)?[^\s,;\"'}]+"
)
INLINE_BEARER = re.compile(r"(?i)\bBearer\s+[^\s,;\"'}]+")


def _redact_response_values(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if SENSITIVE_RESPONSE_KEY.search(str(key))
            else _redact_response_values(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_response_values(item) for item in value]
    return value


def safe_response_preview(body, max_chars=200):
    """Keep short JSON evidence while redacting sensitive values and omitting HTML/text."""
    if not isinstance(body, str):
        return "[non-text response omitted]"
    try:
        parsed = json.loads(body)
        preview = json.dumps(_redact_response_values(parsed), ensure_ascii=False)
    except (json.JSONDecodeError, ValueError, TypeError, RecursionError):
        return f"[non-JSON response omitted; length={len(body)}]"

    preview = INLINE_SECRET_ASSIGNMENT.sub("[REDACTED]", preview)
    preview = INLINE_BEARER.sub("Bearer [REDACTED]", preview)
    preview = INLINE_JWT.sub("[REDACTED]", preview)
    preview = INLINE_EMAIL.sub("[REDACTED]", preview)
    return preview[:max_chars]
