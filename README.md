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

## Features

- **Regex detectors** for AWS access/secret keys, GitHub tokens, Slack
  tokens, PEM private-key headers, and generic `api_key = "…"` assignments.
- **Shannon-entropy detection** catches random-looking strings (rotated key
  formats, custom tokens) that no regex knows; findings carry an `entropy`
  field.
- **JSON output** (`--json`) for piping into other tools.
- **Allowlist config** (`--config allowlist.json`) to silence test fixtures
  and remap severities per finding type.
- **Markdown reports** via `scanner/reporter.py` (`to_markdown`) with
  counts by severity.
- **Pytest suite** in `tests/` covering every detector, the entropy
  detector, snippet redaction, and the reporter.

## What it detects

| Type | Pattern | Severity |
| ---- | ------- | -------- |
| `aws_access_key` | `AKIA…` access key IDs | high |
| `aws_secret_key` | `aws_secret_access_key = "…"` (40 chars) | critical |
| `github_token` | `ghp_…` / `github_pat_…` tokens | critical |
| `slack_token` | `xoxb-…` / `xoxp-…` tokens | high |
| `pem_private_key` | `-----BEGIN … PRIVATE KEY-----` headers | critical |
| `generic_api_key` | `api_key = "…"`, `password = "…"`, etc. | medium |
| `high_entropy_string` | tokens with Shannon entropy ≥ 4.5 | medium |

## Project layout

```
run.py                  # CLI: python3 run.py [--json] [--config FILE] <path>
scanner/
  detectors.py          # regex detectors -> finding dicts
  entropy.py            # Shannon-entropy detector
  engine.py             # directory walk, allowlist, severity mapping
  config.py             # default severities, allowlist, JSON config loading
  reporter.py           # to_markdown(findings) report rendering
samples/                # leaky-sample.txt (fake secrets) and clean-sample.txt
tests/                  # pytest unit tests
docs/USAGE.md           # full usage guide
examples/               # sample pre-commit hook script
```

## Try it

```bash
python3 run.py samples/                 # text report (fixtures allowlisted by default)
python3 run.py --json samples/         # JSON report
python3 -m pytest tests/ -v            # unit tests
```

See [docs/USAGE.md](docs/USAGE.md) for the allowlist config format,
pre-commit hook setup, and CI integration notes.
