"""Cloud KMS key rotation and BigQuery dataset CMEK compliance rules."""

from typing import Any, Dict, List

from fsi_guard.models import ControlMapping, Finding, Severity

MAX_ROTATION_SECONDS = 90 * 24 * 60 * 60  # 90 days


def _parse_rotation_seconds(period: str) -> int:
    cleaned = str(period).strip().lower()
    if cleaned.endswith("s"):
        cleaned = cleaned[:-1]
    try:
        return int(cleaned)
    except ValueError:
        return 0


def check_kms_key_rotation(resource_name: str, config: Dict[str, Any]) -> List[Finding]:
    """Ensure Cloud KMS crypto keys rotate at least every 90 days."""
    period = config.get("rotation_period", "")
    seconds = _parse_rotation_seconds(period)
    if 0 < seconds <= MAX_ROTATION_SECONDS:
        return []
    return [
        Finding(
            rule_id="FSI-KMS-001",
            title="Cloud KMS key rotation period exceeds 90-day FSI limit",
            severity=Severity.HIGH,
            resource_type="google_kms_crypto_key",
            resource_name=resource_name,
            message=f"rotation_period '{period or 'unset'}' must be set and <= 7776000s (90 days).",
            remediation="Set rotation_period = '7776000s' (90 days) or shorter on Cloud KMS keys.",
            controls=[
                ControlMapping("PCI-DSS v4.0", "3.6.4", "Enforce cryptoperiods and regular cryptographic key rotation."),
                ControlMapping("APRA CPS 234", "Paragraph 21", "Maintain lifecycle controls for cryptographic keys."),
            ],
        )
    ]


def check_bigquery_cmek(resource_name: str, config: Dict[str, Any]) -> List[Finding]:
    """Ensure BigQuery datasets use Customer-Managed Encryption Keys (CMEK)."""
    enc = config.get("default_encryption_configuration", {})
    if enc.get("kms_key_name"):
        return []
    return [
        Finding(
            rule_id="FSI-BQ-001",
            title="BigQuery dataset missing CMEK encryption",
            severity=Severity.HIGH,
            resource_type="google_bigquery_dataset",
            resource_name=resource_name,
            message="Dataset does not configure default_encryption_configuration.kms_key_name.",
            remediation="Assign a Cloud KMS key to default_encryption_configuration.kms_key_name.",
            controls=[
                ControlMapping("PCI-DSS v4.0", "3.5.1", "Protect stored financial analytics data with managed keys."),
                ControlMapping("DORA", "Article 9", "Encrypt critical ICT data repositories at rest."),
            ],
        )
    ]


KMS_BQ_RULES = {
    "google_kms_crypto_key": [check_kms_key_rotation],
    "google_bigquery_dataset": [check_bigquery_cmek],
}
