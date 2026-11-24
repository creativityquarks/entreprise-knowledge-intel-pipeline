"""Airflow task 1: source snapshots in GCS, plus per-run manifest."""
import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests
from google.api_core.exceptions import PreconditionFailed
from google.cloud import storage

from core import maven_queries, run_key, sha256

ROOT = Path(__file__).resolve().parents[1]
OSV_URL = "https://storage.googleapis.com/cve-osv-conversion/osv-output/CVE-2021-44228.json"
BATCH_URL = "https://api.osv.dev/v1/querybatch"
LIMIT = 12_000_000


def download(url, payload=None):
    headers = {"User-Agent": "knowledge-airflow-mvp/0.1", "Accept":"application/json"}
    if payload is None:
        response = requests.get(url, headers=headers, timeout=40)
    else:
        response = requests.post(url, json=payload, headers=headers, timeout=40)
    response.raise_for_status()
    raw = response.content
    if len(raw) > LIMIT:
        raise ValueError(f"Source exceeds 12 MB: {url}")
    json.loads(raw)
    return raw, response.headers


def store(bucket, source, raw, ext="json"):
    digest = sha256(raw)
    name = f"raw/{source}/{digest}.{ext}"
    try:
        bucket.blob(name).upload_from_string(
            raw, content_type="application/json", if_generation_match=0
        )
        state = "new"
    except PreconditionFailed:
        state = "reused"
    return digest, f"gs://{bucket.name}/{name}", state


def main(run_id):
    bucket = storage.Client().bucket(os.environ["BRONZE_BUCKET"])
    time = datetime.now(timezone.utc).isoformat()
    records = []
    sboms = []
    for app in ("billing", "analytics"):
        path = ROOT / "fixtures" / f"{app}.json"
        raw = path.read_bytes()
        obj = json.loads(raw)
        sboms.append(obj)
        digest, uri, state = store(bucket, f"sbom_{app}", raw)
        records.append({"source": f"sbom_{app}", "source_url": f"fixture://{app}",
                        "sha256": digest, "gcs_uri": uri, "bytes": len(raw),
                        "storage_status": state, "retrieved_at":time})

    queries = maven_queries(sboms)
    if not queries:
        raise ValueError("No Maven packages to query in inventory")
    if len(queries) > 1000:
        raise ValueError("MVP supports a maximum of 1000 package queries")

    advisory_raw, advisory_headers = download(OSV_URL)
    digest, uri, state = store(bucket, "osv_advisory", advisory_raw)
    records.append({"source":"osv_advisory", "source_url":OSV_URL,
                    "sha256":digest,"gcs_uri":uri,"bytes":len(advisory_raw),
                    "storage_status":state,"retrieved_at":time,
                    "etag":advisory_headers.get("ETag")})

    payload = {"queries":queries}
    batch_raw, batch_headers = download(BATCH_URL, payload)
    batch_obj = json.loads(batch_raw)
    if len(batch_obj.get("results", [])) != len(queries):
        raise ValueError("OSV querybatch result cardinality mismatch")
    if any(r.get("next_page_token") for r in batch_obj["results"]):
        raise ValueError("Paginated OSV batch result unsupported in MVP; use /v1/query")
    digest, uri, state = store(bucket, "osv_batch", batch_raw)
    records.append({"source":"osv_batch", "source_url":BATCH_URL,
                    "sha256":digest,"gcs_uri":uri,"bytes":len(batch_raw),
                    "storage_status":state,"retrieved_at":time,
                    "request_sha256":sha256(json.dumps(payload,sort_keys=True).encode())})

    # Each run keeps its own manifest; unchanged raw content is not recopied.
    manifest = {"run_id":run_id,"run_timestamp":time,"queries":queries,"records":records,
                "note":"SBOMs are synthetic fixtures; OSV responses are live"}
    manifest_path = f"metadata/runs/{run_key(run_id)}.json"
    raw_manifest = json.dumps(manifest, indent=2).encode()
    try:
        bucket.blob(manifest_path).upload_from_string(
            raw_manifest, content_type="application/json", if_generation_match=0)
    except PreconditionFailed:
        # Airflow task retry uses the same run_id; preserve the first immutable manifest.
        pass
    print(json.dumps({"manifest":f"gs://{bucket.name}/{manifest_path}",
                      "statuses":{r["source"]:r["storage_status"] for r in records}},indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    main(parser.parse_args().run_id)
