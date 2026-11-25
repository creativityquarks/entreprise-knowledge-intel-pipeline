"""Read genuine local inventories and verify recorded generator provenance."""
import hashlib
import json
from pathlib import Path

MAX_BYTES = 12_000_000


def read_input(location):
    """Read a bounded local SBOM. Live inputs require a provenance sidecar."""
    path = Path(location)
    with path.open('rb') as stream:
        body = stream.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError('SBOM exceeds 12 MB')
    json.loads(body)
    return body


def provenance(path, body, application_id):
    """Reject missing provenance, mismatched identities or modified SBOMs."""
    path = Path(path)
    meta = json.loads(path.with_suffix('.provenance.json').read_text())
    if meta['application_id'] != application_id:
        raise ValueError('Application identity differs from generator provenance')
    if hashlib.sha256(body).hexdigest() != meta['sbom_sha256']:
        raise ValueError('SBOM provenance hash mismatch')
    for key in ('release_tag', 'repository_url', 'git_commit', 'commit_at', 'java_version', 'maven_version', 'generator_version', 'generated_at'):
        if not isinstance(meta.get(key), str) or not meta[key]:
            raise ValueError(f'Missing SBOM provenance: {key}')
    import re
    if not re.fullmatch(r'[0-9a-f]{40}', meta['git_commit']):
        raise ValueError('Expected resolved Git commit SHA')
    return meta
