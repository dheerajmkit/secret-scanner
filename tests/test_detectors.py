"""Unit tests for detectors, entropy, engine and reporter.

Run with:  python3 -m pytest tests/ -v   (from the repo root)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.detectors import scan_text
from scanner.entropy import find_high_entropy, shannon_entropy
from scanner.reporter import to_markdown


def _types(text):
    return {f["type"] for f in scan_text("f.txt", text)}


def test_aws_access_key():
    assert "aws_access_key" in _types('id = "AKIAIOSFODNN7EXAMPLE"')


def test_aws_secret_key():
    assert "aws_secret_key" in _types(
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12"')


def test_github_token():
    assert "github_token" in _types(
        'token = "ghp_EXAMPLE1234567890abcdefghijklmnopqrs"')


def test_slack_token():
    assert "slack_token" in _types(
        'token = "xoxb-123456789012-EXAMPLE-abcdefghijklmnop"')


def test_pem_private_key():
    assert "pem_private_key" in _types("-----BEGIN RSA PRIVATE KEY----- EXAMPLE")


def test_generic_api_key():
    assert "generic_api_key" in _types('api_key = "sk_test_EXAMPLE_9f8e7d6c5b4a"')


def test_clean_text_ignored():
    assert scan_text("f.txt", 'region = "us-east-1"\n# nothing to see\n') == []


def test_snippet_is_redacted():
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12"
    findings = scan_text("f.txt", f'aws_secret_access_key = "{secret}"')
    assert findings and secret not in findings[0]["snippet"]


def test_finding_keys():
    findings = scan_text("f.txt", 'id = "AKIAIOSFODNN7EXAMPLE"')
    assert set(findings[0]) == {"file", "line", "type", "severity", "snippet"}


def test_entropy_flags_random_string():
    assert shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12") > 4.5


def test_entropy_ignores_plain_text():
    assert find_high_entropy("f.txt", "the quick brown fox jumps over") == []


def test_reporter_counts():
    md = to_markdown(scan_text("f.txt", 'id = "AKIAIOSFODNN7EXAMPLE"'))
    assert "# Secret scan report" in md
    assert "- high: 1" in md
