"""Local content-addressed Bronze storage; hashes cover exact stored bytes."""
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = (ROOT / 'fixtures' / 'snapshots').resolve()

def _gcs_bucket():
    """Return a GCS Bucket object if BRONZE_BUCKET is set, otherwise None (local mode)."""
    name = os.getenv('BRONZE_BUCKET', '').strip()
    if not name:
        return None
    from google.cloud import storage
    return storage.Client().bucket(name)
def utc_now():
    return datetime.now(timezone.utc).isoformat()
def json_bytes(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False) + '\n').encode()
def atomic_write(path, body):
    """Publish a complete file, never a partially written JSON document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temp = Path(stream.name)
        stream.write(body)
    try:
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
def snapshot(data_dir, source, body):
    """Validate JSON and reuse identical bytes within a source directory (local or GCS)."""
    parsed = json.loads(body)
    sha = hashlib.sha256(body).hexdigest()
    rel_path = f'raw/{source}/{sha}.json'
    bucket = _gcs_bucket()
    if bucket is not None:
        from google.api_core.exceptions import PreconditionFailed
        try:
            bucket.blob(rel_path).upload_from_string(
                body, content_type='application/json', if_generation_match=0
            )
            reused = False
        except PreconditionFailed:
            reused = True
    else:
        path = data_dir / rel_path
        reused = path.exists()
        if reused:
            if path.read_bytes() != body:
                raise ValueError(f'Corrupt existing snapshot: {path}')
        else:
            atomic_write(path, body)
    canonical_sha = hashlib.sha256(
        json.dumps(parsed, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    ).hexdigest()
    return {
        'sha256': sha,
        'path': rel_path,
        'bytes': len(body),
        'canonical_sha256': canonical_sha,
        'storage_status': 'reused' if reused else 'saved',
    }
def read_snapshot(data_dir, entry):
    """Reject paths outside Bronze and verify bytes before parsing (local or GCS)."""
    bucket = _gcs_bucket()
    is_local_fixture = Path(data_dir).resolve() == FIXTURES_DIR
    if bucket is not None and not is_local_fixture:
        rel_path = entry['path']
        if not rel_path.startswith('raw/') or '..' in rel_path:
            raise ValueError(f'Invalid snapshot path: {rel_path}')
        body = bucket.blob(rel_path).download_as_bytes()
        label = f'gs://{bucket.name}/{rel_path}'
    else:
        path = (data_dir / entry['path']).resolve()
        if not path.is_relative_to((data_dir / 'raw').resolve()):
            raise ValueError(f'Invalid snapshot path: {path}')
        body = path.read_bytes()
        label = str(path)
    if hashlib.sha256(body).hexdigest() != entry['sha256']:
        raise ValueError(f'Snapshot SHA-256 mismatch: {label}')
    return json.loads(body)
