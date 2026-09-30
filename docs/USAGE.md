# Usage guide

secret-scanner is a personal portfolio project: a pre-commit / CI secret
scanner in pure Python 3 (standard library only). It has never been deployed
at any employer — it exists to demonstrate security-automation skills.

## Install

Nothing to install beyond Python 3. Clone the repo and run from its root:

```bash
git clone https://github.com/dheerajmkit/secret-scanner.git
cd secret-scanner
```

## Basic scan

```bash
python3 run.py <path>
```

Exit code `1` means findings were reported; `0` means the tree is clean.
Snippets are redacted — full secret values never appear in output.

## JSON mode

For piping into other tools:

```bash
python3 run.py --json src/ > findings.json
```

Each finding has `file`, `line`, `type`, `severity`, `snippet`, and an
`entropy` field when the entropy detector fired.

## Allowlist config

Silence known test fixtures or project-specific noise with a JSON config:

```json
{
  "severity": {"generic_api_key": "low"},
  "allowlist": ["EXAMPLE", "test-fixture"]
}
```

```bash
python3 run.py --config allowlist.json <path>
```

The config is checked against the raw source line (before redaction).
Severity overrides remap any finding type.

## Pre-commit hook

```bash
cp examples/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Commits are blocked (non-zero exit) while any finding remains.

## CI integration

Example GitHub Actions step:

```yaml
- name: Scan for hardcoded secrets
  run: python3 run.py .
```

The step fails the build when secrets are detected.

## Tests

```bash
python3 -m pytest tests/ -v
```
