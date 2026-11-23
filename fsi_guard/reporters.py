"""Output formatters (JSON, Markdown, SARIF) for FSI compliance reports."""

import json
from typing import Dict, List

from fsi_guard import __version__
from fsi_guard.models import Finding, Severity


def format_json(findings: List[Finding]) -> str:
    payload = {
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def format_markdown(findings: List[Finding]) -> str:
    if not findings:
        return "# FSI Cloud Compliance Report\n\nNo compliance violations detected.\n"

    lines = [
        "# FSI Cloud Compliance Report",
        "",
        f"**Total findings:** {len(findings)}",
        "",
        "| Severity | Rule ID | Resource | Issue | Frameworks |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        frameworks = ", ".join(f"{c.framework} ({c.control_id})" for c in f.controls)
        lines.append(
            f"| {f.severity.value.upper()} | `{f.rule_id}` | "
            f"`{f.resource_type}.{f.resource_name}` | {f.title} | {frameworks} |"
        )
    return "\n".join(lines) + "\n"


def format_sarif(findings: List[Finding], source_file: str = "iac.json") -> str:
    """Render findings as a SARIF 2.1.0 document for GitHub Code Scanning / CI."""
    level_map: Dict[Severity, str] = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }
    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": level_map[f.severity],
                "message": {"text": f"{f.message} Remediation: {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": source_file},
                        }
                    }
                ],
                "properties": {
                    "resource": f"{f.resource_type}.{f.resource_name}",
                    "severity": f.severity.value,
                },
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "fsi-cloud-compliance-guard",
                        "version": __version__,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
