"""GKE private cluster and Workload Identity compliance rules."""

from typing import Any, Dict, List

from fsi_guard.models import ControlMapping, Finding, Severity


def check_gke_cluster_security(resource_name: str, config: Dict[str, Any]) -> List[Finding]:
    """Ensure GKE clusters enable private nodes and Workload Identity."""
    findings: List[Finding] = []
    private_cfg = config.get("private_cluster_config", {})
    if not private_cfg.get("enable_private_nodes", False):
        findings.append(
            Finding(
                rule_id="FSI-GKE-001",
                title="GKE cluster nodes have public IP addresses",
                severity=Severity.HIGH,
                resource_type="google_container_cluster",
                resource_name=resource_name,
                message="private_cluster_config.enable_private_nodes is not enabled.",
                remediation="Enable private_cluster_config.enable_private_nodes = true.",
                controls=[
                    ControlMapping("PCI-DSS v4.0", "1.3.2", "Restrict outbound/inbound public exposure of compute nodes."),
                    ControlMapping("DORA", "Article 9", "Isolate critical containerized workloads inside private networks."),
                ],
            )
        )
    wi_cfg = config.get("workload_identity_config", {})
    if not wi_cfg.get("workload_pool"):
        findings.append(
            Finding(
                rule_id="FSI-GKE-002",
                title="GKE Workload Identity is not enabled",
                severity=Severity.MEDIUM,
                resource_type="google_container_cluster",
                resource_name=resource_name,
                message="workload_identity_config.workload_pool is unset.",
                remediation="Configure workload_identity_config.workload_pool to avoid static service account keys.",
                controls=[
                    ControlMapping("SOC 2", "CC6.1", "Use federated short-lived workload credentials."),
                ],
            )
        )
    return findings


GKE_RULES = {"google_container_cluster": [check_gke_cluster_security]}
