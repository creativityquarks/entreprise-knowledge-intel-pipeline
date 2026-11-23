PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS snapshots (sha256 TEXT PRIMARY KEY, source TEXT NOT NULL, url TEXT, provenance TEXT NOT NULL, captured_utc TEXT NOT NULL, raw_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS vulnerabilities (vuln_id TEXT PRIMARY KEY, ecosystem TEXT NOT NULL, package_name TEXT NOT NULL, introduced TEXT NOT NULL, fixed TEXT NOT NULL, advisory_snapshot TEXT NOT NULL REFERENCES snapshots(sha256));
CREATE TABLE IF NOT EXISTS aliases (vuln_id TEXT NOT NULL REFERENCES vulnerabilities(vuln_id), alias TEXT NOT NULL, PRIMARY KEY(vuln_id,alias));
CREATE TABLE IF NOT EXISTS inventory_components (run_id INTEGER NOT NULL, app TEXT NOT NULL, bom_ref TEXT NOT NULL, package_name TEXT, version TEXT, purl TEXT, inventory_snapshot TEXT NOT NULL REFERENCES snapshots(sha256), PRIMARY KEY(run_id,app,bom_ref));
CREATE TABLE IF NOT EXISTS dependencies (run_id INTEGER NOT NULL, app TEXT NOT NULL, parent_ref TEXT NOT NULL, child_ref TEXT NOT NULL, inventory_snapshot TEXT NOT NULL REFERENCES snapshots(sha256), PRIMARY KEY(run_id,app,parent_ref,child_ref));
CREATE TABLE IF NOT EXISTS exposures (run_id INTEGER NOT NULL, app TEXT NOT NULL, package_name TEXT NOT NULL, version TEXT NOT NULL, vuln_id TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('affected','not_affected','unknown')), path TEXT NOT NULL, inventory_evidence TEXT NOT NULL REFERENCES snapshots(sha256), advisory_evidence TEXT NOT NULL REFERENCES snapshots(sha256), PRIMARY KEY(run_id,app,package_name,version,vuln_id));
CREATE INDEX IF NOT EXISTS idx_deps_parent ON dependencies(run_id,app,parent_ref);
CREATE INDEX IF NOT EXISTS idx_exposure_status ON exposures(run_id,status);
