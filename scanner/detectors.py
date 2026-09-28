"""Regex detectors for hardcoded secrets.

scan_text(filename, text) returns finding dicts with the keys:
file, line, type, severity, snippet. Snippets are redacted so the
full secret value never leaves the report.
"""
import re

_PATTERNS = [
    # (finding type, compiled regex, default severity)
    ("aws_access_key",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "high"),
    ("aws_secret_key",
     re.compile(r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
     "critical"),
    ("github_token",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"
                r"|\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
     "critical"),
    ("slack_token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     "high"),
    ("pem_private_key",
     re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "critical"),
    ("generic_api_key",
     re.compile(r"(?i)\b(api[_-]?key|secret|passwd|password|token)\b"
                r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-.~+/=]{16,})['\"]?"),
     "medium"),
]


def _redact(line, match):
    """Mask the matched secret, keeping the surrounding context."""
    value = match.group(0)
    masked = value[:4] + "...[redacted]"
    start, end = match.span()
    return (line[:start] + masked + line[end:]).strip()[:160]


def scan_text(filename, text):
    """Scan a text blob; return a list of finding dicts."""
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        claimed = []  # spans already reported by a specific detector
        ordered = [p for p in _PATTERNS if p[0] != "generic_api_key"]
        ordered.append(next(p for p in _PATTERNS if p[0] == "generic_api_key"))
        for ftype, pattern, severity in ordered:
            for match in pattern.finditer(line):
                span = match.span()
                if ftype == "generic_api_key" and any(
                    s < span[1] and span[0] < e for s, e in claimed
                ):
                    continue  # a specific detector already owns this span
                findings.append({
                    "file": filename,
                    "line": lineno,
                    "type": ftype,
                    "severity": severity,
                    "snippet": _redact(line, match),
                })
                claimed.append(span)
    return findings
