import argparse
import json
import sys

from .checks import scan
from .loader import load_document
from .models import SEVERITIES, Finding


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Find common security issues in OpenAPI 3 documents")
    parser.add_argument("document", help="Path to an OpenAPI JSON or YAML document")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format")
    parser.add_argument("--fail-on", choices=SEVERITIES, default="high", help="Exit 1 when this severity or higher is found")
    return parser


def _text(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    return "\n".join(f"[{finding.severity.upper():6}] {finding.rule}: {finding.message} ({finding.location})" for finding in findings)


def _failed(findings: list[Finding], threshold: str) -> bool:
    return any(SEVERITIES.index(finding.severity) <= SEVERITIES.index(threshold) for finding in findings)


def main() -> int:
    args = _parser().parse_args()
    try:
        findings = scan(load_document(args.document))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps([finding.as_dict() for finding in findings], indent=2))
    else:
        print(_text(findings))
    return 1 if _failed(findings, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
