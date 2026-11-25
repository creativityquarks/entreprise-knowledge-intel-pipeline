CREATE TABLE IF NOT EXISTS `{{PROJECT_ID}}.{{DATASET}}.component_findings` (
  source_sha256 STRING NOT NULL,
  bom_ref STRING NOT NULL,
  vulnerability_id STRING NOT NULL,
  osv_query_sha256 STRING NOT NULL
);
