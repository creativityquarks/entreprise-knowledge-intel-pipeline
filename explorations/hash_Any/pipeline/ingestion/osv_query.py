"""
Execute supplementary OSV package-version queries during Bronze ingestion.

- Extract Maven components with reliable group, artifact, and version fields.
- Query https://api.osv.dev/v1/query per component.
- Deduplicate raw response bytes via storage.save_snapshot("osv_queries", ...).
- Record every attempt (SUCCESS or FAILED) so failures are never mistaken for 0 findings.
"""

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

from ingestion.manifest import register_snapshot
from ingestion.providers import osv
from ingestion.storage import compute_hash, save_snapshot

MAX_SIZE = 5_000_000
TIMEOUT = 30


def extract_maven_components(sbom_raw: bytes) -> list[dict]:
    """Return Maven components that have bom-ref, group, name (artifact), and version."""
    sbom = json.loads(sbom_raw)
    maven_components: list[dict] = []

    for comp in sbom.get("components", []):
        purl = comp.get("purl", "")
        group = comp.get("group")
        artifact = comp.get("name")
        version = comp.get("version")
        bom_ref = comp.get("bom-ref")

        # Require reliable Maven coordinates; skip non-Maven PURLs if a PURL is present
        if purl and not purl.startswith("pkg:maven/"):
            continue
        if not (bom_ref and group and artifact and version):
            continue

        maven_components.append({
            "bom_ref": bom_ref,
            "ecosystem": "Maven",
            "group": group,
            "artifact": artifact,
            "package_name": f"{group}:{artifact}",
            "installed_version": version,
        })

    return maven_components


def post_osv_query(package_name: str, version: str) -> tuple[bytes, dict]:
    """POST an exact-version query to OSV and return raw bytes + HTTP metadata."""
    payload = {
        "package": {"ecosystem": "Maven", "name": package_name},
        "version": version,
    }
    request = urllib.request.Request(
        osv.QUERY_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "knowledge-mvp/0.2",
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        raw = response.read(MAX_SIZE + 1)
        if len(raw) > MAX_SIZE:
            raise ValueError("OSV query response size limit exceeded")

        json.loads(raw)  # Validate JSON before persisting

        metadata = {
            "source_url": osv.QUERY_URL,
            "package_name": package_name,
            "installed_version": version,
            "size_bytes": len(raw),
            "content_type": response.headers.get("Content-Type"),
        }

    return raw, metadata


def query_sbom_components(
    sbom_sha256: str,
    sbom_raw: bytes,
    run_id: str,
) -> tuple[list[dict], set[str]]:
    """Query OSV for every Maven component in an SBOM and snapshot the responses."""
    components = extract_maven_components(sbom_raw)
    query_records: list[dict] = []
    discovered_vuln_ids: set[str] = set()

    for comp in components:
        checked_at = datetime.now(timezone.utc).isoformat()
        record = {
            "sbom_sha256": sbom_sha256,
            "bom_ref": comp["bom_ref"],
            "ecosystem": comp["ecosystem"],
            "package_name": comp["package_name"],
            "installed_version": comp["installed_version"],
            "query_sha256": None,
            "query_status": None,
            "checked_at": checked_at,
            "snapshot_path": None,
            "matched_osv_ids": [],
            "error": None,
        }

        try:
            raw, metadata = post_osv_query(
                comp["package_name"], comp["installed_version"]
            )
            query_sha256 = compute_hash(raw)
            file_path = save_snapshot("osv_queries", raw, query_sha256)
            register_snapshot(
                source="osv_queries",
                sha256=query_sha256,
                file_path=file_path,
                metadata=metadata,
                run_id=run_id,
            )

            parsed = json.loads(raw)
            matched_ids = [v["id"] for v in parsed.get("vulns", []) if "id" in v]
            discovered_vuln_ids.update(matched_ids)

            record.update({
                "query_sha256": query_sha256,
                "query_status": "SUCCESS",
                "snapshot_path": str(file_path),
                "matched_osv_ids": matched_ids,
            })

        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            record.update({
                "query_status": "FAILED",
                "error": f"{type(error).__name__}: {error}",
            })

        query_records.append(record)

    return query_records, discovered_vuln_ids
