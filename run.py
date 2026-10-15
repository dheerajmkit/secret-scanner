#!/usr/bin/env python3
"""CLI entry point: scan a path for hardcoded secrets.

Usage:
    python3 run.py [--json] [--config FILE] <path>

Exits 1 when findings are present, 0 when the tree is clean.
"""
import argparse
import json
import sys

from scanner import config as config_module
from scanner.engine import configure, scan_path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Scan a directory tree for hardcoded secrets.")
    parser.add_argument("path", help="file or directory to scan")
    parser.add_argument("--json", dest="as_json", action="store_true",
                        help="emit findings as JSON")
    parser.add_argument("--config", metavar="FILE",
                        help="JSON config with severity overrides / allowlist")
    args = parser.parse_args(argv)

    configure(config_module.load_config(args.config) if args.config else None)
    findings = scan_path(args.path)

    if args.as_json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            extra = f" (entropy {f['entropy']})" if "entropy" in f else ""
            print(f"{f['file']}:{f['line']} [{f['severity']}]"
                  f" {f['type']}{extra}: {f['snippet']}")
        print(f"\n{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
