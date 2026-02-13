#!/usr/bin/env python3
"""ValGap CLI — detect validation gaps in Python API models."""
import argparse
import sys
from pathlib import Path
from valgap_analyzer import analyze_source
from valgap_reporter import SARIFReporter, JSONReporter, TextReporter


def scan_path(path: Path) -> list:
    files = list(path.rglob("*.py")) if path.is_dir() else [path]
    results = []
    for f in files:
        try:
            source = f.read_text(encoding="utf-8")
            for gap in analyze_source(source, str(f)):
                results.append((str(f), gap))
        except (SyntaxError, UnicodeDecodeError):
            print(f"\u26a0\ufe0f  Skipping {f}", file=sys.stderr)
    return results


def main():
    parser = argparse.ArgumentParser(prog="valgap", description="Validation gap detector")
    parser.add_argument("paths", nargs="+", help="Python files or directories to scan")
    parser.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("-s", "--min-severity", choices=["low", "medium", "high"], default="low")
    parser.add_argument("-o", "--output", help="Write output to file instead of stdout")
    args = parser.parse_args()
    sev_rank = {"low": 0, "medium": 1, "high": 2}
    results = []
    for p in args.paths:
        results.extend(scan_path(Path(p)))
    results = [(f, g) for f, g in results if sev_rank[g.severity] >= sev_rank[args.min_severity]]

    output = None
    if args.output:
        output = open(args.output, "w", encoding="utf-8")

    try:
        if args.format == "json":
            reporter = JSONReporter(results)
        elif args.format == "sarif":
            reporter = SARIFReporter(results)
        else:
            reporter = TextReporter(results)
        reporter.write(output)
    finally:
        if output:
            output.close()

    sys.exit(1 if results else 0)


if __name__ == "__main__":
    main()
