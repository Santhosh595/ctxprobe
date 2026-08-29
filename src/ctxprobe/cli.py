"""Command-line entry point for ctxprobe."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from .scanner import Finding, scan_path, scan_text, SEVERITY_ORDER


def _human(f: Finding) -> str:
    return (
        f"[{f.severity.upper():6}] {f.file}:{f.line}:{f.column} "
        f"({f.source}) {f.family}: {f.match!r}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctxprobe",
        description="Scan markdown/HTML/text for context-poisoning / prompt-injection patterns.",
    )
    parser.add_argument(
        "command",
        choices=["scan"],
        help="Scan a file, directory, or stdin for injection patterns.",
    )
    parser.add_argument("--path", help="Path to a file or directory to scan.")
    parser.add_argument("--stdin", action="store_true", help="Read content from stdin.")
    parser.add_argument(
        "--format",
        choices=["auto", "html", "markdown", "text"],
        default="auto",
        help="Force a parser (default: auto-detect).",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the human-readable report (still sets exit code).",
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Only report findings at or above this severity (default: low).",
    )
    return parser


def _filter(findings: List[Finding], min_sev: str) -> List[Finding]:
    threshold = SEVERITY_ORDER[min_sev]
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= threshold]


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.stdin:
        raw = sys.stdin.read()
        findings = scan_text(raw, fmt=args.format, file_label="<stdin>")
    elif args.path:
        findings = scan_path(args.path, fmt=args.format)
    else:
        parser.error("one of --path or --stdin is required")

    findings = _filter(findings, args.min_severity)
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.file, f.line))

    if args.json:
        payload = {
            "findings": [f.to_dict() for f in findings],
            "total": len(findings),
            "summary": {
                sev: sum(1 for f in findings if f.severity == sev)
                for sev in ("high", "medium", "low")
            },
        }
        print(json.dumps(payload, indent=2))
    elif not args.quiet:
        if not findings:
            print("No findings detected.")
        else:
            for f in findings:
                print(_human(f))
            hi = sum(1 for f in findings if f.severity == "high")
            med = sum(1 for f in findings if f.severity == "medium")
            lo = sum(1 for f in findings if f.severity == "low")
            print(f"\n{len(findings)} finding(s): {hi} high, {med} medium, {lo} low")

    # Exit codes: 0 clean, 1 findings, 2 usage/IO error.
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
