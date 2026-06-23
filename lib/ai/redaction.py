"""Optional redaction helpers for AI context."""

from __future__ import annotations

import re

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*")
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def redact_text(text: str) -> str:
    """Best-effort redaction of common secret patterns."""
    redacted = _EMAIL.sub("[REDACTED_EMAIL]", text)
    redacted = _IPV4.sub("[REDACTED_IP]", redacted)
    redacted = _BEARER.sub(r"\1[REDACTED_TOKEN]", redacted)
    redacted = _AWS_KEY.sub("[REDACTED_AWS_KEY]", redacted)
    redacted = _JWT.sub("[REDACTED_JWT]", redacted)
    return redacted
