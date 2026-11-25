CREATE TABLE IF NOT EXISTS `{{PROJECT_ID}}.{{DATASET}}.component_queries` (
  source_sha256 STRING NOT NULL,
  bom_ref STRING NOT NULL,
  package_name STRING,
  component_version STRING,
  osv_query_sha256 STRING,
  raw_response_path STRING,
  queried_at TIMESTAMP NOT NULL,
  status STRING NOT NULL,
  ecosystem STRING,
  error STRING
);
