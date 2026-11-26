# FSI Cloud Compliance Guard — Policy Catalog

| Rule ID | Resource Type | Severity | Frameworks |
|---|---|---|---|
| `FSI-STOR-001` | `google_storage_bucket` | HIGH | PCI-DSS v4.0 3.5.1, APRA CPS 234 |
| `FSI-STOR-002` | `google_storage_bucket` | CRITICAL | PCI-DSS v4.0 1.3.1, SOC 2 CC6.1 |
| `FSI-STOR-003` | `google_storage_bucket` | MEDIUM | SOC 2 CC6.3 |
| `FSI-DB-001` | `google_sql_database_instance` | CRITICAL | PCI-DSS v4.0 1.4.2, DORA Art. 9 |
| `FSI-DB-002` | `google_sql_database_instance` | HIGH | PCI-DSS v4.0 4.2.1, APRA CPS 234 |
| `FSI-IAM-001` | `google_project_iam_binding` | HIGH | PCI-DSS v4.0 7.2.2, SOC 2 CC6.3 |
| `FSI-IAM-002` | `google_project_iam_binding` | CRITICAL | APRA CPS 234, DORA Art. 9 |
| `FSI-LOG-001` | `google_logging_project_bucket_config` | HIGH | PCI-DSS v4.0 10.5.1, DORA Art. 12 |
| `FSI-LOG-002` | `google_logging_project_bucket_config` | MEDIUM | PCI-DSS v4.0 10.3.2 |
| `FSI-NET-001` | `google_access_context_manager_service_perimeter` | HIGH | APRA CPS 234, DORA Art. 9 |
| `FSI-KMS-001` | `google_kms_crypto_key` | HIGH | PCI-DSS v4.0 3.6.4, APRA CPS 234 |
| `FSI-BQ-001` | `google_bigquery_dataset` | HIGH | PCI-DSS v4.0 3.5.1, DORA Art. 9 |
| `FSI-GKE-001` | `google_container_cluster` | HIGH | PCI-DSS v4.0 1.3.2, DORA Art. 9 |
| `FSI-GKE-002` | `google_container_cluster` | MEDIUM | SOC 2 CC6.1 |
