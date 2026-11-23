CREATE SCHEMA IF NOT EXISTS lab;

CREATE TABLE IF NOT EXISTS lab.snapshots (
  snapshot_id TEXT PRIMARY KEY, -- SHA-256 of original bytes
  source_name TEXT NOT NULL,
  source_url TEXT,
  captured_utc TIMESTAMPTZ,
  raw_document JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS lab.components (
  inventory_run INTEGER NOT NULL,
  bom_ref TEXT NOT NULL,
  component_type TEXT,
  component_name TEXT NOT NULL,
  ecosystem TEXT,
  package_name TEXT,
  installed_version TEXT,
  purl TEXT,
  evidence_sha256 TEXT NOT NULL REFERENCES lab.snapshots(snapshot_id),
  PRIMARY KEY (inventory_run, bom_ref)
);

CREATE TABLE IF NOT EXISTS lab.dependency_edges (
  inventory_run INTEGER NOT NULL,
  parent_ref TEXT NOT NULL,
  child_ref TEXT NOT NULL,
  evidence_sha256 TEXT NOT NULL REFERENCES lab.snapshots(snapshot_id),
  PRIMARY KEY (inventory_run,parent_ref,child_ref),
  FOREIGN KEY (inventory_run,parent_ref)
    REFERENCES lab.components(inventory_run,bom_ref),
  FOREIGN KEY (inventory_run,child_ref)
    REFERENCES lab.components(inventory_run,bom_ref)
);

CREATE TABLE IF NOT EXISTS lab.affected_packages (
  advisory_snapshot TEXT NOT NULL REFERENCES lab.snapshots(snapshot_id),
  cve_id TEXT NOT NULL,
  affected_index INTEGER NOT NULL,
  ecosystem TEXT,
  package_name TEXT,
  ranges JSONB NOT NULL,
  explicit_versions JSONB NOT NULL DEFAULT '[]'::jsonb,
  PRIMARY KEY (advisory_snapshot,affected_index)
);

CREATE TABLE IF NOT EXISTS lab.exposure_results (
  inventory_run INTEGER NOT NULL,
  component_ref TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('affected','not_affected','unknown')),
  reason TEXT,
  advisory_snapshot TEXT NOT NULL REFERENCES lab.snapshots(snapshot_id),
  inventory_snapshot TEXT NOT NULL REFERENCES lab.snapshots(snapshot_id),
  PRIMARY KEY (inventory_run,component_ref,cve_id),
  FOREIGN KEY (inventory_run,component_ref)
    REFERENCES lab.components(inventory_run,bom_ref)
);
