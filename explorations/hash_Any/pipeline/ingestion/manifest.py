"""
Manage the Bronze snapshot manifest.

- Maintain a single historical registry of raw snapshots.
- Use SHA-256 hashes as content identity keys.
- Register only previously unseen content.
- Preserve source metadata and ingestion lineage.
- Update the manifest atomically to prevent partial writes.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

# Define the manifest location
ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "data" / "bronze" / "manifest" / "manifest.json"


def load_manifest() -> dict:
    """Load the existing manifest or initialize its structure."""

    if MANIFEST_PATH.exists():
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    return {
        "schema_version": 1,
        "sources": {
            "osv": {},
            "sbom": {},
        },
    }


def save_manifest(manifest: dict) -> None:
    """Persist the manifest using an atomic file replacement."""

    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temporary file before replacing the manifest
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

    # Skip previously registered content
    if sha256 in snapshots:
        return False

    # Register the new snapshot and its provenance
    snapshots[sha256] = {
        **metadata,
        "raw_path": str(file_path.relative_to(ROOT)),
        "first_seen_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
    }

    save_manifest(manifest)

    return True
