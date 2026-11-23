"""Storage and database encryption & network exposure rules for FSI workloads."""

from typing import Any, Dict, List

from fsi_guard.models import ControlMapping, Finding, Severity


def check_storage_cmek(resource_name: str, config: Dict[str, Any]) -> List[Finding]:
    """Ensure cloud storage buckets use Customer-Managed Encryption Keys (CMEK)."""
    encryption = config.get("encryption", {})
    kms_key = encryption.get("default_kms_key_name")
    if kms_key:
        return []
    return [
        Finding(
            rule_id="FSI-STOR-001",
            title="Storage bucket missing CMEK encryption",
            severity=Severity.HIGH,
            resource_type="google_storage_bucket",
            resource_name=resource_name,
            message="Bucket does not specify a customer-managed KMS key (CMEK).",
            remediation="Configure encryption.default_kms_key_name with a Cloud KMS key.",
            controls=[
                ControlMapping("PCI-DSS v4.0", "3.5.1", "Protect stored account data with strong cryptography and key management."),
                ControlMapping("APRA CPS 234", "Paragraph 21", "Maintain information security controls commensurate with asset sensitivity."),
            ],
        )
    ]


def check_storage_public_access(resource_name: str, config: Dict[str, Any]) -> List[Finding]:
    """Ensure storage buckets enforce public access prevention."""
    pap = config.get("public_access_prevention", "inherited")
    uniform = config.get("uniform_bucket_level_access", False)
    findings: List[Finding] = []
    if pap != "enforced":
        findings.append(
            Finding(
                rule_id="FSI-STOR-002",
                title="Storage bucket public access prevention not enforced",
                severity=Severity.CRITICAL,
                resource_type="google_storage_bucket",
                resource_name=resource_name,
                message=f"public_access_prevention is '{pap}' instead of 'enforced'.",
                remediation="Set public_access_prevention = 'enforced' on the bucket.",
                controls=[
                    ControlMapping("PCI-DSS v4.0", "1.3.1", "Restrict inbound traffic to cardholder data environments."),
                    ControlMapping("SOC 2", "CC6.1", "Restrict logical access to protected data assets."),
                ],
            )
        )
    if not uniform:
        findings.append(
            Finding(
                rule_id="FSI-STOR-003",
                title="Uniform bucket-level access disabled",
                severity=Severity.MEDIUM,
                resource_type="google_storage_bucket",
                resource_name=resource_name,
                message="Legacy object ACLs are permitted; uniform_bucket_level_access is false.",
                remediation="Enable uniform_bucket_level_access = true to centralize IAM access control.",
                controls=[
                    ControlMapping("SOC 2", "CC6.3", "Authorize access based on least privilege and role-based policies."),
                ],
            )
        )
    return findings


def check_sql_security(resource_name: str, config: Dict[str, Any]) -> List[Finding]:
    """Ensure Cloud SQL instances disable public IPs and enforce TLS."""
    settings = config.get("settings", {})
    ip_config = settings.get("ip_configuration", {})
    findings: List[Finding] = []

    if ip_config.get("ipv4_enabled", True):
        findings.append(
            Finding(
                rule_id="FSI-DB-001",
                title="Cloud SQL instance exposes public IPv4 address",
                severity=Severity.CRITICAL,
                resource_type="google_sql_database_instance",
                resource_name=resource_name,
                message="Database instance has ipv4_enabled = true, exposing it beyond private VPC.",
                remediation="Set ip_configuration.ipv4_enabled = false and connect via Private Service Connect.",
                controls=[
                    ControlMapping("PCI-DSS v4.0", "1.4.2", "Prohibit direct public access between untrusted networks and system components storing CHD."),
                    ControlMapping("DORA", "Article 9", "Implement network segmentation and protection for critical ICT assets."),
                ],
            )
        )

    if not ip_config.get("require_ssl", False):
        findings.append(
            Finding(
                rule_id="FSI-DB-002",
                title="Cloud SQL instance does not enforce TLS/SSL",
                severity=Severity.HIGH,
                resource_type="google_sql_database_instance",
                resource_name=resource_name,
                message="ip_configuration.require_ssl is not enabled.",
                remediation="Enable require_ssl = true (or ssl_mode = 'ENCRYPTED_ONLY').",
                controls=[
                    ControlMapping("PCI-DSS v4.0", "4.2.1", "Protect PAN with strong cryptography during transmission."),
                    ControlMapping("APRA CPS 234", "Paragraph 21", "Protect sensitive financial data in transit."),
                ],
            )
        )
    return findings


STORAGE_DB_RULES = {
    "google_storage_bucket": [check_storage_cmek, check_storage_public_access],
    "google_sql_database_instance": [check_sql_security],
}
