"""Unit tests for FSI Cloud Compliance Guard."""

import json
import unittest
from pathlib import Path

from fsi_guard.models import Severity
from fsi_guard.reporters import format_json, format_markdown, format_sarif
from fsi_guard.scanner import ComplianceScanner

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


class TestComplianceScanner(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = ComplianceScanner()

    def test_compliant_config_has_zero_findings(self) -> None:
        findings = self.scanner.scan_file(EXAMPLES_DIR / "compliant_gcp.json")
        self.assertEqual(findings, [])
        self.assertFalse(self.scanner.should_fail_gate(findings, Severity.LOW))

    def test_non_compliant_config_flags_all_controls(self) -> None:
        findings = self.scanner.scan_file(EXAMPLES_DIR / "non_compliant_gcp.json")
        rule_ids = {f.rule_id for f in findings}
        expected = {
            "FSI-STOR-001",
            "FSI-STOR-002",
            "FSI-STOR-003",
            "FSI-DB-001",
            "FSI-DB-002",
            "FSI-IAM-001",
            "FSI-IAM-002",
            "FSI-LOG-001",
            "FSI-LOG-002",
            "FSI-NET-001",
        }
        self.assertEqual(rule_ids, expected)
        self.assertTrue(self.scanner.should_fail_gate(findings, Severity.CRITICAL))

    def test_sarif_and_json_reporters_produce_valid_json(self) -> None:
        findings = self.scanner.scan_file(EXAMPLES_DIR / "non_compliant_gcp.json")
        parsed_json = json.loads(format_json(findings))
        self.assertEqual(parsed_json["total_findings"], len(findings))

        parsed_sarif = json.loads(format_sarif(findings, "examples/non_compliant_gcp.json"))
        self.assertEqual(parsed_sarif["version"], "2.1.0")
        self.assertEqual(len(parsed_sarif["runs"][0]["results"]), len(findings))

    def test_markdown_reporter_clean_output(self) -> None:
        output = format_markdown([])
        self.assertIn("No compliance violations detected", output)


if __name__ == "__main__":
    unittest.main()
