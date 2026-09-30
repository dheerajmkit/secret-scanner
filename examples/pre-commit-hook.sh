#!/bin/sh
# Sample pre-commit hook: block commits when secret-scanner finds secrets.
#
# Install:
#   cp examples/pre-commit-hook.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Runs from the repo root. Default allowlist silences labeled test
# fixtures (see scanner/config.py).
set -u

if ! python3 run.py . > /tmp/secret-scan.out 2>&1; then
    echo "secret-scanner: hardcoded secrets detected - commit blocked."
    cat /tmp/secret-scan.out
    exit 1
fi
exit 0
