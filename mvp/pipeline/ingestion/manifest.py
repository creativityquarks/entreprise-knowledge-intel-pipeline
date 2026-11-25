"""Publish one complete run manifest, retaining all query attempts and lineage.

The run manifests plus content-addressed files replace the mutable global
registry in fetch_v2; a registry can be rebuilt by replaying these manifests.
"""
from .storage import atomic_write, json_bytes


def save_run_manifest(data_dir, manifest):
    path = data_dir / 'metadata' / 'runs' / (manifest['run_id'] + '.json')
    if path.exists():
        raise FileExistsError(path)
    atomic_write(path, json_bytes(manifest))
    return path
