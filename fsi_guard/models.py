"""Core data models for FSI compliance rules, controls, and findings."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]


@dataclass(frozen=True)
class ControlMapping:
    """Maps a technical security rule to regulatory FSI controls."""

    framework: str
    control_id: str
    description: str


@dataclass(frozen=True)
class Finding:
    """Represents a single policy violation detected in an IaC resource."""

    rule_id: str
    title: str
    severity: Severity
    resource_type: str
    resource_name: str
    message: str
    remediation: str
    controls: List[ControlMapping] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "message": self.message,
            "remediation": self.remediation,
            "controls": [
                {
                    "framework": c.framework,
                    "control_id": c.control_id,
                    "description": c.description,
                }
                for c in self.controls
            ],
        }
