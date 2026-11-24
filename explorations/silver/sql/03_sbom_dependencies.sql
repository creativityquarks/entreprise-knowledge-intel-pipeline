CREATE TABLE IF NOT EXISTS `{{PROJECT_ID}}.{{DATASET}}.sbom_dependencies` (
  sbom_id STRING NOT NULL,
  source_sha256 STRING NOT NULL,
  parent_bom_ref STRING NOT NULL,
  child_bom_ref STRING NOT NULL
);
