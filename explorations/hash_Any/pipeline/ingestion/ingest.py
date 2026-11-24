"""Coordinate the Bronze ingestion workflow (SBOMs -> OSV queries -> OSV advisories)."""

import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

from ingestion.manifest import register_snapshot, save_query_run_manifest
from ingestion.osv_query import query_sbom_components
from ingestion.providers import osv, sbom
from ingestion.storage import compute_hash, save_snapshot

MAX_SIZE = 5_000_000  # 5 MB
TIMEOUT = 30  # seconds


def fetch_json(url: str, max_size: int = MAX_SIZE) -> tuple[bytes, dict]:
    """Retrieve raw JSON data and its associated HTTP metadata."""
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "knowledge-mvp/0.2",
        },
    )

    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        raw = response.read(max_size + 1)
        if len(raw) > max_size:
            raise ValueError("Response size limit exceeded")

        json.loads(raw)  # Validate JSON without modifying original bytes

        metadata = {
            "source_url": url,
            "size_bytes": len(raw),
            "content_type": response.headers.get("Content-Type"),
            "etag": response.headers.get("ETag"),
            "last_modified": response.headers.get("Last-Modified"),
        }

    return raw, metadata


def main() -> None:
    """Execute the Bronze ingestion workflow."""
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

    # 1. Ingest SBOMs and run supplementary OSV package-version queries
    all_query_records: list[dict] = []
    discovered_vuln_ids: set[str] = set()

    for sbom_id in sbom.SOURCES:
        url = sbom.get_url(sbom_id)
        try:
            raw, metadata = fetch_json(url)
        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            print(f"[ERROR] Run {run_id} | SBOM | {sbom_id} | {error}", file=sys.stderr)
            sys.exit(1)

        metadata["application_id"] = sbom_id
        sbom_sha256 = compute_hash(raw)
        file_path = save_snapshot("sbom", raw, sbom_sha256)
        registered = register_snapshot(
            source="sbom",
            sha256=sbom_sha256,
            file_path=file_path,
            metadata=metadata,
            run_id=run_id,
        )

        print(
            f"SBOM {sbom_id} | SHA-256: {sbom_sha256[:12]} | "
            f"Manifest: {'updated' if registered else 'unchanged'}"
        )

        # Query OSV for every Maven component inside this SBOM
        records, found_ids = query_sbom_components(sbom_sha256, raw, run_id)
        all_query_records.extend(records)
        discovered_vuln_ids.update(found_ids)

        for rec in records:
            print(
                f"  Query {rec['package_name']}@{rec['installed_version']} -> "
                f"{rec['query_status']} ({len(rec['matched_osv_ids'])} matches)"
            )

    # Persist per-run query log (preserves 0-match and failed lookups for Silver)
    query_manifest_path = save_query_run_manifest(run_id, all_query_records)
    print(f"Query run manifest: {query_manifest_path}\n")

    # 2. Ingest full OSV advisories (baseline + any newly discovered IDs from queries)
    baseline_ids = {"CVE-2021-44228", "CVE-2021-45046"}
    all_vuln_ids = sorted(baseline_ids | discovered_vuln_ids)

    for vuln_id in all_vuln_ids:
        url = osv.get_vuln_api_url(vuln_id)
        try:
            raw, metadata = fetch_json(url)
        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            print(f"[ERROR] Run {run_id} | OSV | {vuln_id} | {error}", file=sys.stderr)
            sys.exit(1)

        sha256 = compute_hash(raw)
        file_path = save_snapshot("osv", raw, sha256)
        registered = register_snapshot(
            source="osv",
            sha256=sha256,
            file_path=file_path,
            metadata=metadata,
            run_id=run_id,
        )
        print(
            f"OSV {vuln_id} | SHA-256: {sha256[:12]} | "
            f"Manifest: {'updated' if registered else 'unchanged'}"
        )


if __name__ == "__main__":
    main()
