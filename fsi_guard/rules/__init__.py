"""Compliance rule registry for FSI Cloud Compliance Guard."""

from typing import Callable, Dict, List

from fsi_guard.models import Finding
from fsi_guard.rules.iam_network import IAM_NETWORK_RULES
from fsi_guard.rules.kms_bq import KMS_BQ_RULES
from fsi_guard.rules.storage_db import STORAGE_DB_RULES

RuleFn = Callable[[str, Dict], List[Finding]]


def get_all_rules() -> Dict[str, List[RuleFn]]:
    """Merge all rule groups by Terraform/GCP resource type."""
    registry: Dict[str, List[RuleFn]] = {}
    for group in (STORAGE_DB_RULES, IAM_NETWORK_RULES, KMS_BQ_RULES):
        for resource_type, rules in group.items():
            registry.setdefault(resource_type, []).extend(rules)
    return registry


__all__ = ["STORAGE_DB_RULES", "IAM_NETWORK_RULES", "KMS_BQ_RULES", "get_all_rules"]
