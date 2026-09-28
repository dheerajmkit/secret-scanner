# secret-scanner

A lightweight pre-commit / CI secret scanner written in pure Python 3
(standard library only). It walks a directory tree and flags hardcoded
credentials — AWS keys, GitHub tokens, Slack tokens, PEM private keys,
and generic API keys — *before* they get committed.

This is a **personal portfolio project** exploring security automation and
shift-left detection. It is a learning exercise, not a production tool, and
it has never been deployed at any employer.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 run.py <path>
```

Example:

```bash
python3 run.py samples/
```

A finding looks like:

```
samples/leaky-sample.txt:2 [high] aws_access_key: aws_access_key_id = "AKIA...[redacted]"
```

The exit code is `1` when findings are present and `0` when the tree is
clean, so the scanner can gate a commit or a CI step. Snippets are
redacted — the full secret value never appears in output.

## What it detects (day 1)

| Type | Pattern | Severity |
| ---- | ------- | -------- |
| `aws_access_key` | `AKIA…` access key IDs | high |
| `aws_secret_key` | `aws_secret_access_key = "…"` (40 chars) | critical |
| `github_token` | `ghp_…` / `github_pat_…` tokens | critical |
| `slack_token` | `xoxb-…` / `xoxp-…` tokens | high |
| `pem_private_key` | `-----BEGIN … PRIVATE KEY-----` headers | critical |
| `generic_api_key` | `api_key = "…"`, `password = "…"`, etc. | medium |

## Project layout

```
run.py            # CLI entry point: python3 run.py <path>
scanner/          # detection engine (detectors.py, engine.py)
samples/          # leaky-sample.txt (fake secrets) and clean-sample.txt
```

## Roadmap

- **Day 2:** Shannon-entropy detection for random-looking strings, JSON
  output, and an allowlist config to silence known test fixtures.
- **Day 3:** Markdown reporting, pytest unit tests, usage docs, and a
  sample pre-commit hook.
