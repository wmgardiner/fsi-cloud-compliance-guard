"""Command-line interface for FSI Cloud Compliance Guard."""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from fsi_guard.models import Severity
from fsi_guard.reporters import format_json, format_markdown, format_sarif
from fsi_guard.scanner import ComplianceScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fsi-guard",
        description="Scan cloud IaC JSON configs for FSI security & regulatory compliance.",
    )
    parser.add_argument("target", type=Path, help="Path to Terraform/IaC JSON file.")
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "sarif"],
        default="markdown",
        help="Report output format (default: markdown).",
    )
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default="high",
        help="Exit non-zero when a finding meets or exceeds this severity (default: high).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    scanner = ComplianceScanner()
    findings = scanner.scan_file(args.target)

    if args.format == "json":
        print(format_json(findings))
    elif args.format == "sarif":
        print(format_sarif(findings, source_file=str(args.target)))
    else:
        print(format_markdown(findings))

    threshold = Severity(args.fail_on)
    return 1 if scanner.should_fail_gate(findings, threshold) else 0


if __name__ == "__main__":
    sys.exit(main())
