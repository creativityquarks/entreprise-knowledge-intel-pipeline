CREATE TABLE IF NOT EXISTS `{{PROJECT_ID}}.{{DATASET}}.sbom_components` (
  sbom_id STRING NOT NULL,
  source_sha256 STRING NOT NULL,
  bom_ref STRING,
  component_index INT64 NOT NULL,
  name STRING NOT NULL,
  group_name STRING,
  version STRING,
  purl STRING,
  component_type STRING,
  is_root BOOL
);
