"""Publish one complete run manifest, retaining all query attempts and lineage.

The run manifests plus content-addressed files replace the mutable global
registry in fetch_v2; a registry can be rebuilt by replaying these manifests.
"""
from .storage import _gcs_bucket, atomic_write, json_bytes


def save_run_manifest(data_dir, manifest):
    rel_path = f"metadata/runs/{manifest['run_id']}.json"
    bucket = _gcs_bucket()
    if bucket is not None:
        from google.api_core.exceptions import PreconditionFailed
        try:
            bucket.blob(rel_path).upload_from_string(
                json_bytes(manifest), content_type='application/json', if_generation_match=0
            )
        except PreconditionFailed:
            raise FileExistsError(f"gs://{bucket.name}/{rel_path}")
        return f"gs://{bucket.name}/{rel_path}"
    path = data_dir / rel_path
    if path.exists():
        raise FileExistsError(path)
    atomic_write(path, json_bytes(manifest))
    return path
