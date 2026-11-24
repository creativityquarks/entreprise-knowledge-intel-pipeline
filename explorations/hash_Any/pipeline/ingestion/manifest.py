"""
Manage the Bronze snapshot manifest and per-run OSV query logs.

- Maintain a single historical registry of raw snapshots keyed by SHA-256.
- Preserve every attempted package query per run (including 0-match and failures).
- Update manifest files atomically to prevent partial writes.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "data" / "bronze" / "manifest" / "manifest.json"
RUNS_DIR = ROOT / "data" / "bronze" / "manifest" / "runs"


def load_manifest() -> dict:
    """Load the existing manifest or initialize its structure."""
    if MANIFEST_PATH.exists():
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    return {
        "schema_version": 1,
        "sources": {
            "osv": {},
            "sbom": {},
            "osv_queries": {},
        },
    }


def save_manifest(manifest: dict) -> None:
    """Persist the manifest using an atomic file replacement."""
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = MANIFEST_PATH.with_suffix(".tmp")
    temp_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    temp_path.replace(MANIFEST_PATH)


def register_snapshot(
    source: str,
    sha256: str,
    file_path: Path,
    metadata: dict,
    run_id: str,
) -> bool:
    """Register a new snapshot only if its hash is unknown."""
    manifest = load_manifest()
    snapshots = manifest["sources"].setdefault(source, {})

    if sha256 in snapshots:
        return False

    snapshots[sha256] = {
        **metadata,
        "raw_path": str(file_path.relative_to(ROOT)),
        "first_seen_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
    }

    save_manifest(manifest)
    return True


def save_query_run_manifest(run_id: str, records: list[dict]) -> Path:
    """Persist every attempted OSV package query for a run (successes and failures)."""
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    target_path = RUNS_DIR / f"{run_id}_osv_queries.json"
    temp_path = target_path.with_suffix(".tmp")

    payload = {
        "schema_version": 1,
        "run_id": run_id,
        "queries": records,
    }
    temp_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temp_path.replace(target_path)
    return target_path
