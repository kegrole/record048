"""Command-line entry point.

Usage: python -m cachepoison.cli --cases demo/cases.json --out out/report.json
"""

import argparse
import json
import sys

from .detector import analyze_cases
from .report import build_report, summary_line


def load_cases(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        return data.get("cases", []), data.get("config")
    return data, None


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="cachepoison",
        description="Detect cache-key confusion / web cache poisoning risks.",
    )
    parser.add_argument("--cases", required=True, help="path to cases JSON")
    parser.add_argument("--out", help="write the JSON report to this path")
    args = parser.parse_args(argv)

    cases, default_config = load_cases(args.cases)
    results = analyze_cases(cases, default_config)
    report = build_report(results)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")

    print(summary_line(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
