-- Run via bq query after substituting PROJECT_ID. Datasets must exist (location EU).
CREATE TABLE IF NOT EXISTS `PROJECT_ID.vulnerability_silver.applications` (
  row_key STRING, application_id STRING, application_name STRING, first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);
CREATE TABLE IF NOT EXISTS `PROJECT_ID.vulnerability_silver.sboms` (
  row_key STRING, source_sha256 STRING, application_id STRING, root_bom_ref STRING,
  source_uri STRING, first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);
CREATE TABLE IF NOT EXISTS `PROJECT_ID.vulnerability_silver.sbom_components` (
  row_key STRING, source_sha256 STRING, bom_ref STRING, component_name STRING,
  component_group STRING, component_version STRING, package_name STRING, purl STRING,
  is_root BOOL, first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);
CREATE TABLE IF NOT EXISTS `PROJECT_ID.vulnerability_silver.sbom_dependencies` (
  row_key STRING, source_sha256 STRING, parent_bom_ref STRING, child_bom_ref STRING,
  first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);
CREATE TABLE IF NOT EXISTS `PROJECT_ID.vulnerability_silver.vulnerabilities` (
  row_key STRING, source_sha256 STRING, vulnerability_id STRING, summary STRING,
  published_at STRING, modified_at STRING, advisory_url STRING,
  first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);
CREATE TABLE IF NOT EXISTS `PROJECT_ID.vulnerability_silver.affected_packages` (
  row_key STRING, source_sha256 STRING, vulnerability_id STRING, affected_index INT64,
  ecosystem STRING, package_name STRING, first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);
CREATE TABLE IF NOT EXISTS `PROJECT_ID.vulnerability_silver.affected_version_events` (
  row_key STRING, source_sha256 STRING, vulnerability_id STRING, affected_index INT64,
  range_index INT64, event_index INT64, range_type STRING, event_type STRING,
  event_value STRING, first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);
-- Direct exact-version results from OSV querybatch, not an improvised Maven comparator.
CREATE TABLE IF NOT EXISTS `PROJECT_ID.vulnerability_silver.component_findings` (
  row_key STRING, source_sha256 STRING, application_id STRING, bom_ref STRING,
  component_name STRING, package_name STRING, component_version STRING,
  vulnerability_id STRING, query_sha256 STRING,
  first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS `PROJECT_ID.vulnerability_bronze.source_snapshots` (
  row_key STRING, source_name STRING, sha256 STRING, source_url STRING,
  gcs_uri STRING, size_bytes INT64, first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);
CREATE TABLE IF NOT EXISTS `PROJECT_ID.vulnerability_bronze.ingestion_runs` (
  row_key STRING, run_id STRING, source_name STRING, sha256 STRING,
  retrieved_at STRING, storage_status STRING, gcs_uri STRING,
  first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);
