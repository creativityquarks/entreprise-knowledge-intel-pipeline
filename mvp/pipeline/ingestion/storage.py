"""Local content-addressed Bronze storage; hashes cover exact stored bytes."""
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def _gcs_bucket():
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
    """Validate JSON and reuse identical bytes within a source directory."""
    json.loads(body)
    sha = hashlib.sha256(body).hexdigest()
    path = data_dir / 'raw' / source / f'{sha}.json'
    reused = path.exists()
    if reused:
        if path.read_bytes() != body:
            raise ValueError(f'Corrupt existing snapshot: {path}')
    else:
        atomic_write(path, body)
    return {'sha256': sha, 'path': path.relative_to(data_dir).as_posix(),
            'bytes': len(body), 'canonical_sha256': hashlib.sha256(json.dumps(json.loads(body), sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest(), 'storage_status': 'reused' if reused else 'saved'}


def read_snapshot(data_dir, entry):
    """Reject paths outside Bronze and verify bytes before parsing."""
    path = (data_dir / entry['path']).resolve()
    if not path.is_relative_to((data_dir / 'raw').resolve()):
        raise ValueError(f'Invalid snapshot path: {path}')
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != entry['sha256']:
        raise ValueError(f'Snapshot SHA-256 mismatch: {path}')
    return json.loads(body)
