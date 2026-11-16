"""Offline CBOM runner: scan a directory for quantum-vulnerable crypto and
write a CycloneDX 1.6 CBOM. No API key or network needed.

    python3 scan_cbom.py [PATH] [-o cbom.json]

This is the runner role: it scans once, builds the Report, and hands that to
the reporter. reporters/cbom_reporter.py stays pure formatting and never
calls into checks/.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from checks.crypto_check import scan_crypto
from context.report import build_report
from reporters.cbom_reporter import render_cbom, write_cbom


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emit a CycloneDX 1.6 CBOM of quantum-vulnerable crypto.")
    parser.add_argument("path", nargs="?", default=".", help="directory to scan (default: current directory)")
    parser.add_argument("-o", "--output", help="write the CBOM to this file instead of stdout")
    args = parser.parse_args(argv)

    target = Path(args.path)
    if not target.is_dir():
        print(f"error: {args.path!r} is not a directory", file=sys.stderr)
        return 2

    result = scan_crypto(target)
    report = build_report(str(target), result.findings, crypto_assets=result.assets)

    if args.output:
        write_cbom(report, args.output)
        print(f"Wrote CBOM with {len(result.assets)} component(s) to {args.output}", file=sys.stderr)
    else:
        print(render_cbom(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
