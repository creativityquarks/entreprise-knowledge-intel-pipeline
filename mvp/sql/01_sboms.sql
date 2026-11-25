CREATE TABLE IF NOT EXISTS `{{PROJECT_ID}}.{{DATASET}}.sboms` (
  sbom_id STRING NOT NULL,
  serial_number STRING,
  spec_version STRING,
  version INT64,
  metadata_timestamp TIMESTAMP,
  root_component_ref STRING,
  source_sha256 STRING NOT NULL,
  retrieved_at TIMESTAMP NOT NULL,
  release_tag STRING,
  repository_url STRING,
  git_commit STRING,
  commit_at TIMESTAMP,
  java_version STRING,
  maven_version STRING,
  generator_version STRING,
  generated_at TIMESTAMP
);
