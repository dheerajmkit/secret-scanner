"""Shannon-entropy detector for random-looking credential strings.

Catches secrets that no regex knows about (rotated key formats, custom
tokens) by flagging long, high-entropy strings. Findings carry an
``entropy`` field; the finding type is ``high_entropy_string``.
"""
import math
import re
from collections import Counter

_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")
DEFAULT_THRESHOLD = 4.5
MIN_LENGTH = 20


def shannon_entropy(value):
    """Return the Shannon entropy (bits per char) of ``value``."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def find_high_entropy(filename, text, threshold=DEFAULT_THRESHOLD):
    """Flag tokens with entropy >= ``threshold``; return finding dicts."""
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for match in _TOKEN.finditer(line):
            token = match.group(0)
            if len(token) < MIN_LENGTH:
                continue
            entropy = shannon_entropy(token)
            if entropy < threshold:
                continue
            masked = token[:4] + "...[redacted]"
            start, end = match.span()
            snippet = (line[:start] + masked + line[end:]).strip()[:160]
            findings.append({
                "file": filename,
                "line": lineno,
                "type": "high_entropy_string",
                "severity": "medium",
                "snippet": snippet,
                "entropy": round(entropy, 2),
            })
    return findings
