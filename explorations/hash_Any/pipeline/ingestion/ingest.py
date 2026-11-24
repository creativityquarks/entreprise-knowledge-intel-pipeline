"""
Coordinate the Bronze ingestion workflow.

- Retrieve raw JSON data from configured sources.
- Enforce response size limits and HTTP timeouts.
- Validate JSON responses before further processing.
- Collect HTTP metadata for provenance and manifest registration.
- Preserve the original response bytes.
- Store immutable raw snapshots using SHA-256 content identification.
- Register new snapshots in the historical ingestion manifest.
- Report extraction failures with source and run context.
"""

import json
import urllib.request
from datetime import datetime, timezone

from ingestion.providers import osv
from ingestion.storage import compute_hash, save_snapshot
from ingestion.manifest import register_snapshot

import sys
import urllib.error

# Define HTTP extraction limits
MAX_SIZE = 5_000_000  # 5 MB
TIMEOUT = 30  # seconds


def fetch_json(url: str, max_size: int = MAX_SIZE) -> tuple[bytes, dict]:
    """Retrieve raw JSON data and its associated HTTP metadata."""

    # Prepare the HTTP request
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json"},
    )

    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:

        # Read the response and detect oversized payloads
        raw = response.read(max_size + 1)

        if len(raw) > max_size:
            raise ValueError("Response size limit exceeded")

        # Validate JSON without modifying the original bytes
        json.loads(raw)

        # Collect metadata for provenance and manifest registration
        metadata = {
            "source_url": url,
            "size_bytes": len(raw),
            "content_type": response.headers.get("Content-Type"),
            "etag": response.headers.get("ETag"),
            "last_modified": response.headers.get("Last-Modified"),
        }

    return raw, metadata


def main():
    """Execute the Bronze ingestion workflow."""

    # Generate a unique identifier for the ingestion run
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

    # Define OSV vulnerabilities to ingest
    vulnerability_ids = [
        "CVE-2021-44228",
        "CVE-2021-45046",
    ]

    for vulnerability_id in vulnerability_ids:

        # Resolve the OSV source URL
        url = osv.get_url(vulnerability_id)

        # Retrieve and validate raw data
        try:
            raw, metadata = fetch_json(url)

        except (
            urllib.error.URLError,
            TimeoutError,
            ValueError,
        ) as error:
            print(
                f"[ERROR] Run {run_id} | OSV | "
                f"{vulnerability_id} | {error}",
                file=sys.stderr,
            )
            sys.exit(1)

        # Generate the content identity
        sha256 = compute_hash(raw)

        # Store the immutable raw snapshot
        file_path = save_snapshot("osv", raw, sha256)

        # Register the snapshot only if the hash is new
        registered = register_snapshot(
            source="osv",
            sha256=sha256,
            file_path=file_path,
            metadata=metadata,
            run_id=run_id,
        )

        # Display ingestion results
        print("Run ID:", run_id)
        print("Vulnerability:", vulnerability_id)
        print("SHA-256:", sha256)
        print("Snapshot:", file_path)
        print("Manifest:", "updated" if registered else "unchanged")
        print()


# Execute the workflow when the module is run directly
if __name__ == "__main__":
    main()
