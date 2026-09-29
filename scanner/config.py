"""Scan configuration: default severities and allowlist.

A config is a plain dict::

    {"severity": {"generic_api_key": "low"},
     "allowlist": [compiled regex, ...]}

loadable from a JSON file via load_config(). The built-in ALLOWLIST
covers labels used in test fixtures (e.g. "EXAMPLE"); extend it via
--config for project-specific noise.
"""
import json
import re

DEFAULT_SEVERITY = {
    "aws_access_key": "high",
    "aws_secret_key": "critical",
    "github_token": "critical",
    "slack_token": "high",
    "pem_private_key": "critical",
    "generic_api_key": "medium",
    "high_entropy_string": "medium",
}

ALLOWLIST = [
    r"EXAMPLE",  # labels in test/sample fixtures
    r"AKIAIOSFODNN7EXAMPLE",
]


def default_config():
    """Return the default config dict."""
    return {
        "severity": dict(DEFAULT_SEVERITY),
        "allowlist": [re.compile(p) for p in ALLOWLIST],
    }


def load_config(path):
    """Load a JSON config file; returns a config dict.

    The file may contain {"severity": {...}, "allowlist": ["regex", ...]}.
    File values override/extend the defaults.
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    severity = dict(DEFAULT_SEVERITY)
    severity.update(data.get("severity", {}))
    patterns = list(ALLOWLIST) + list(data.get("allowlist", []))
    return {
        "severity": severity,
        "allowlist": [re.compile(p) for p in patterns],
    }
