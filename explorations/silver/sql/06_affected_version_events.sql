CREATE TABLE IF NOT EXISTS `{{PROJECT_ID}}.{{DATASET}}.affected_version_events` (
  osv_id STRING NOT NULL,
  source_sha256 STRING NOT NULL,
  affected_index INT64 NOT NULL,
  range_index INT64 NOT NULL,
  range_type STRING,
  event_index INT64 NOT NULL,
  event_type STRING,
  event_value STRING
);
