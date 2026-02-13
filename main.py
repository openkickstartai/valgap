#!/usr/bin/env python3
"""ValGap CLI — detect validation gaps in Python API models."""
import argparse
import json
import sys
from pathlib import Path
from valgap_analyzer import analyze_source, to_sarif


def scan_path(path: Path) -> list:
    files = list(path.rglob("*.py")) if path.is_dir() else [path]
    results = []
    for f in files:
        try:
            source = f.read_text(encoding="utf-8")
            for gap in analyze_source(source, str(f)):
                results.append((str(f), gap))
        except (SyntaxError, UnicodeDecodeError):
            print(f"⚠️  Skipping {f}", file=sys.stderr)
    return results


def print_text(results):
    if not results:
        print("✅ No validation gaps found.")
        return
    print(f"\n🔍 Found {len(results)} validation gap(s):\n")
    for filepath, g in results:
        icon = {"high": "🔴", "medium": "🟡", "low": "🔵"}[g.severity]
        print(f"  {icon} {filepath} → {g.model}.{g.field}")
        print(f"     [{g.gap_type}] {g.description}")
        preview = [repr(s)[:50] for s in g.samples[:3]]
        print(f"     Samples: {', '.join(preview)}\n")


def main():
    parser = argparse.ArgumentParser(prog="valgap", description="Validation gap detector")
    parser.add_argument("paths", nargs="+", help="Python files or directories to scan")
    parser.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("-s", "--min-severity", choices=["low", "medium", "high"], default="low")
    args = parser.parse_args()
    sev_rank = {"low": 0, "medium": 1, "high": 2}
    results = []
    for p in args.paths:
        results.extend(scan_path(Path(p)))
    results = [(f, g) for f, g in results if sev_rank[g.severity] >= sev_rank[args.min_severity]]
    if args.format == "text":
        print_text(results)
    elif args.format == "json":
        data = [{"file": f, "model": g.model, "field": g.field, "gap_type": g.gap_type,
                 "severity": g.severity, "description": g.description,
                 "samples": [str(s) for s in g.samples]} for f, g in results]
        print(json.dumps(data, indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif([g for _, g in results], args.paths[0]), indent=2))
    sys.exit(1 if results else 0)


if __name__ == "__main__":
    main()
