"""IaC configuration scanner and CI/CD severity gating engine."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fsi_guard.models import Finding, Severity
from fsi_guard.rules import get_all_rules


class ComplianceScanner:
    """Evaluates Terraform JSON / IaC resource bundles against FSI rules."""

    def __init__(self, rules: Optional[Dict[str, List]] = None) -> None:
        self.rules = rules if rules is not None else get_all_rules()

    def scan_dict(self, iac_data: Dict[str, Any]) -> List[Finding]:
        """Scan an in-memory Terraform-like resource dictionary."""
        findings: List[Finding] = []
        resources = iac_data.get("resource", {})

        for resource_type, instances in resources.items():
            evaluators = self.rules.get(resource_type, [])
            if not evaluators:
                continue
            for resource_name, config in instances.items():
                if isinstance(config, dict):
                    for evaluator in evaluators:
                        findings.extend(evaluator(resource_name, config))

        findings.sort(key=lambda f: (-f.severity.rank, f.rule_id, f.resource_name))
        return findings

    def scan_file(self, path: Path) -> List[Finding]:
        """Load a JSON IaC file and return sorted compliance findings."""
        data = json.loads(path.read_text(encoding="utf-8"))
        return self.scan_dict(data)

    @staticmethod
    def should_fail_gate(findings: List[Finding], fail_on: Severity) -> bool:
        """Return True if any finding meets or exceeds the configured severity gate."""
        return any(f.severity.rank >= fail_on.rank for f in findings)
