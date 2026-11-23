CREATE SCHEMA IF NOT EXISTS live;

CREATE TABLE IF NOT EXISTS live.snapshots (
  source_name TEXT PRIMARY KEY,
  source_url TEXT NOT NULL,
  retrieved_utc TIMESTAMPTZ NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS live.osv_affected (
  source_name TEXT NOT NULL REFERENCES live.snapshots(source_name),
  cve_id TEXT NOT NULL,
  affected_index INTEGER NOT NULL,
  ecosystem TEXT,
  package_name TEXT,
  ranges JSONB NOT NULL,
  explicit_versions JSONB NOT NULL,
  PRIMARY KEY (source_name,affected_index)
);

CREATE TABLE IF NOT EXISTS live.sbom_components (
  bom_ref TEXT PRIMARY KEY,
  component_name TEXT NOT NULL,
  component_group TEXT,
  version TEXT,
  purl TEXT,
  component_type TEXT
);

CREATE TABLE IF NOT EXISTS live.sbom_edges (
  parent_ref TEXT NOT NULL REFERENCES live.sbom_components(bom_ref),
  child_ref TEXT NOT NULL REFERENCES live.sbom_components(bom_ref),
  PRIMARY KEY (parent_ref,child_ref)
);

CREATE TABLE IF NOT EXISTS live.advisory_aliases (
  source_name TEXT NOT NULL REFERENCES live.snapshots(source_name),
  cve_id TEXT NOT NULL,
  alias_id TEXT NOT NULL,
  PRIMARY KEY (source_name,cve_id,alias_id)
);
