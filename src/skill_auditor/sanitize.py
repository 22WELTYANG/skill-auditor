"""Safe, deterministic text rendering for untrusted metadata and errors."""

from __future__ import annotations

import re
import urllib.parse

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_URL_RE = re.compile(r"(?:https?|ssh|file)://[^\s]+", re.IGNORECASE)
_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|authorization)"
    r"(\s*[:=]\s*)[^\s,;]+"
)
_BIDI = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def safe_display(value: object) -> str:
    """Remove terminal controls and credentials from attacker-controlled text."""

    text = _ANSI_RE.sub("", str(value))
    output: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character in "\r\n\t":
            output.append(" ")
        elif (
            codepoint < 32
            or 127 <= codepoint <= 159
            or 0xD800 <= codepoint <= 0xDFFF
            or character in _BIDI
        ):
            output.append(f"\\u{codepoint:04x}")
        else:
            output.append(character)
    rendered = "".join(output)
    rendered = _URL_RE.sub(_redact_url, rendered)
    return _SECRET_RE.sub(r"\1\2[REDACTED]", rendered)


def _redact_url(match: re.Match[str]) -> str:
    matched = match.group(0)
    raw = matched.rstrip(".,;)")
    suffix = matched[len(raw):]
    try:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parsed.port:
            host += f":{parsed.port}"
        sanitized = urllib.parse.urlunsplit(
            (parsed.scheme.lower(), host, parsed.path, "", "")
        )
    except (TypeError, ValueError):
        sanitized = raw.split(":", 1)[0] + "://[REDACTED]"
    return sanitized + suffix
