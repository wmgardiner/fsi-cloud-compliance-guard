"""IAM least-privilege, VPC Service Controls, and audit logging rules."""

from typing import Any, Dict, List

from fsi_guard.models import ControlMapping, Finding, Severity

PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def check_iam_binding(resource_name: str, config: Dict[str, Any]) -> List[Finding]:
    """Detect primitive IAM roles and public principal bindings."""
    role = config.get("role", "")
    members = config.get("members", [])
    if "member" in config:
        members = [*members, config["member"]]

    findings: List[Finding] = []
    if role in PRIMITIVE_ROLES:
        findings.append(
            Finding(
                rule_id="FSI-IAM-001",
                title="Overly permissive primitive IAM role assigned",
                severity=Severity.HIGH,
                resource_type="google_project_iam_binding",
                resource_name=resource_name,
                message=f"Primitive role '{role}' grants broad access across all project services.",
                remediation="Replace primitive roles with granular predefined or custom IAM roles.",
                controls=[
                    ControlMapping("PCI-DSS v4.0", "7.2.2", "Assign access based on job classification and least privilege."),
                    ControlMapping("SOC 2", "CC6.3", "Enforce role-based access control and least privilege."),
                ],
            )
        )

    exposed = [m for m in members if m in PUBLIC_MEMBERS]
    if exposed:
        findings.append(
            Finding(
                rule_id="FSI-IAM-002",
                title="Public IAM principal granted access",
                severity=Severity.CRITICAL,
                resource_type="google_project_iam_binding",
                resource_name=resource_name,
                message=f"Public principal(s) {exposed} bound to role '{role}'.",
                remediation="Remove allUsers/allAuthenticatedUsers and bind specific service accounts or groups.",
                controls=[
                    ControlMapping("APRA CPS 234", "Paragraph 15", "Prevent unauthorized access to information assets."),
                    ControlMapping("DORA", "Article 9", "Enforce strict identity and access management policies."),
                ],
            )
        )
    return findings


def check_audit_log_sink(resource_name: str, config: Dict[str, Any]) -> List[Finding]:
    """Ensure immutable log retention and valid retention period (>= 365 days for FSI)."""
    retention_days = int(config.get("retention_days", 0))
    locked = bool(config.get("locked", False))
    findings: List[Finding] = []

    if retention_days < 365:
        findings.append(
            Finding(
                rule_id="FSI-LOG-001",
                title="Audit log retention below FSI 365-day minimum",
                severity=Severity.HIGH,
                resource_type="google_logging_project_bucket_config",
                resource_name=resource_name,
                message=f"Log bucket retention is {retention_days} days; PCI-DSS requires at least 365 days.",
                remediation="Set retention_days >= 365 on central security audit log buckets.",
                controls=[
                    ControlMapping("PCI-DSS v4.0", "10.5.1", "Retain audit log history for at least 12 months."),
                    ControlMapping("DORA", "Article 12", "Maintain audit trails for incident investigation and resilience testing."),
                ],
            )
        )
    if not locked:
        findings.append(
            Finding(
                rule_id="FSI-LOG-002",
                title="Audit log bucket retention policy is not locked (WORM)",
                severity=Severity.MEDIUM,
                resource_type="google_logging_project_bucket_config",
                resource_name=resource_name,
                message="Audit log bucket is mutable; locked = false.",
                remediation="Enable locked = true to enforce tamper-evident WORM log retention.",
                controls=[
                    ControlMapping("PCI-DSS v4.0", "10.3.2", "Protect audit log files from unauthorized modification."),
                ],
            )
        )
    return findings


def check_vpc_sc_perimeter(resource_name: str, config: Dict[str, Any]) -> List[Finding]:
    """Ensure VPC Service Controls perimeters protect sensitive GCP APIs."""
    restricted = set(config.get("restricted_services", []))
    required = {"storage.googleapis.com", "bigquery.googleapis.com", "kms.googleapis.com"}
    missing = sorted(required - restricted)
    if not missing:
        return []
    return [
        Finding(
            rule_id="FSI-NET-001",
            title="VPC Service Controls perimeter missing core FSI services",
            severity=Severity.HIGH,
            resource_type="google_access_context_manager_service_perimeter",
            resource_name=resource_name,
            message=f"Perimeter omits required restricted services: {', '.join(missing)}.",
            remediation="Add storage, bigquery, and kms APIs to restricted_services to prevent data exfiltration.",
            controls=[
                ControlMapping("APRA CPS 234", "Paragraph 21", "Protect against unauthorized data exfiltration."),
                ControlMapping("DORA", "Article 9", "Implement perimeter controls for critical financial data stores."),
            ],
        )
    ]


IAM_NETWORK_RULES = {
    "google_project_iam_binding": [check_iam_binding],
    "google_project_iam_member": [check_iam_binding],
    "google_logging_project_bucket_config": [check_audit_log_sink],
    "google_access_context_manager_service_perimeter": [check_vpc_sc_perimeter],
}
