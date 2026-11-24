"""
Manage Bronze raw snapshot storage.

- Generate SHA-256 hashes for content identification.
- Prevent duplicate raw snapshots.
- Preserve original source data without modification.
- Return snapshot paths for manifest registration.
"""

import hashlib
from pathlib import Path

# Resolve the MVP root directory
ROOT = Path(__file__).resolve().parents[2]

# Define the Bronze raw storage location
RAW_DIR = ROOT / "data" / "bronze" / "raw"


def compute_hash(raw: bytes) -> str:
    """Generate a SHA-256 hash from the original response bytes."""
    return hashlib.sha256(raw).hexdigest()


def save_snapshot(source: str, raw: bytes, sha256: str) -> Path:
    """Store an immutable raw snapshot and prevent duplicate files."""

    # Identify the snapshot by source and content hash
    file_path = RAW_DIR / source / f"{sha256}.json"

    # Create the source directory if necessary
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Save only if the snapshot does not already exist
    if not file_path.exists():
        # Exclusive binary mode prevents overwriting
        with file_path.open("xb") as file:
            file.write(raw)

    # Return the path for manifest registration
    return file_path
