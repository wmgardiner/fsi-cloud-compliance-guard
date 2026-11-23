# FSI Cloud Compliance Guard

A lightweight Python policy-as-code scanner for Financial Services Industry (FSI) cloud infrastructure configurations. It inspects Terraform/IaC JSON definitions for security misconfigurations and maps findings directly to regulated financial control frameworks.

## Supported Frameworks
- **PCI-DSS v4.0** (Payment Card Industry Data Security Standard)
- **APRA CPS 234** (Information Security for APRA-regulated entities)
- **DORA** (EU Digital Operational Resilience Act)
- **SOC 2** (Trust Services Criteria)

## Quick Start

```bash
python3 -m fsi_guard.cli examples/non_compliant_gcp.json --format markdown
python3 -m fsi_guard.cli examples/non_compliant_gcp.json --format sarif --fail-on high
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
