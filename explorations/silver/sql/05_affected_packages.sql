CREATE TABLE IF NOT EXISTS `{{PROJECT_ID}}.{{DATASET}}.affected_packages` (
  osv_id STRING NOT NULL,
  source_sha256 STRING NOT NULL,
  affected_index INT64 NOT NULL,
  ecosystem STRING,
  package_name STRING,
  package_purl STRING,
  affected_versions ARRAY<STRING>
);
