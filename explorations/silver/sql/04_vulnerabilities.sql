CREATE TABLE IF NOT EXISTS `{{PROJECT_ID}}.{{DATASET}}.vulnerabilities` (
  osv_id STRING NOT NULL,
  summary STRING,
  published_at TIMESTAMP,
  modified_at TIMESTAMP,
  withdrawn_at TIMESTAMP,
  aliases STRING,
  source_sha256 STRING NOT NULL,
  retrieved_at TIMESTAMP NOT NULL
);
