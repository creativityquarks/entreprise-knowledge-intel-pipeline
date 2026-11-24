
"""Fetch live JSON data and avoid storing duplicate files."""

import hashlib
import json
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
DEST = ROOT / "data" / "raw"
MANIFEST_DIR = ROOT / "data" / "metadata" / "runs"

SOURCES = {
    "osv_log4shell": "https://storage.googleapis.com/cve-osv-conversion/osv-output/CVE-2021-44228.json",
    "github_log4shell": "https://api.github.com/advisories/GHSA-jfh8-c2jp-5v3q",
    "github_advisories_page1": "https://api.github.com/advisories?per_page=5&page=1",
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cyclonedx_dependencies": "https://raw.githubusercontent.com/CycloneDX/bom-examples/master/CBOM/Example-With-Dependencies/bom.json",
}


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)

    results = []

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

    for name, url in SOURCES.items():
        record = {
            "name": name,
            "url": url,
            "retrieved_utc": datetime.now(timezone.utc).isoformat(),
        }

        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "knowledge-protocol-feasibility/0.1",
                    "Accept": "application/json",
                },
            )

            with urllib.request.urlopen(req, timeout=25) as resp:
                raw = resp.read(12_000_001)

                if len(raw) > 12_000_000:
                    raise ValueError("Size cap exceeded (12 MB)")

                obj = json.loads(raw)
                sha256 = hashlib.sha256(raw).hexdigest()

                # Store files by source and content hash
                source_dir = DEST / name
                source_dir.mkdir(parents=True, exist_ok=True)

                file_path = source_dir / f"{sha256}.json"

                # Deduplicate identical content
                if file_path.exists():
                    storage_status = "reused"
                else:
                    file_path.write_bytes(raw)
                    storage_status = "saved"

                record.update({
                    "status": "downloaded",
                    "status_code": resp.status,
                    "sha256": sha256,
                    "bytes": len(raw),
                    "etag": resp.headers.get("ETag"),
                    "last_modified": resp.headers.get("Last-Modified"),
                    "top_level_keys": list(obj)[:30] if isinstance(obj, dict) else ["ARRAY"],
                    "link_header": resp.headers.get("Link"),
                    "storage_status": storage_status,
                    "file_path": str(file_path.relative_to(ROOT)),
                })

        except Exception as e:
            record.update({
                "status": "failed",
                "error": f"{type(e).__name__}: {e}",
            })

        results.append(record)
        print(name, record["status"], record.get("storage_status", ""))

    # Keep a separate manifest for every ingestion run
    manifest_path = MANIFEST_DIR / f"{run_id}.json"
    manifest_path.write_text(json.dumps(results, indent=2) + "\n")

    print("Manifest:", manifest_path)


if __name__ == "__main__":
    main()
