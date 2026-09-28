#!/usr/bin/env python3
"""CLI entry point: scan a path for hardcoded secrets.

Usage:
    python3 run.py <path>

Exits 1 when findings are present, 0 when the tree is clean.
"""
import sys

from scanner.engine import scan_path


def main(argv):
    if len(argv) != 2:
        print("usage: python3 run.py <path>", file=sys.stderr)
        return 2
    findings = scan_path(argv[1])
    for f in findings:
        print(f"{f['file']}:{f['line']} [{f['severity']}] {f['type']}: {f['snippet']}")
    print(f"\n{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
