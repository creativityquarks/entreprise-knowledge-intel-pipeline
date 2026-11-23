"""Export observed relationships from the real captured CycloneDX SBOM in PG.

No vulnerability edges: these would require a verified full Maven matcher.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data' / 'outputs'
OUT.mkdir(parents=True, exist_ok=True)

with psycopg.connect(os.environ['DATABASE_URL']) as conn:
    with conn.cursor() as cur:
        cur.execute('''
            SELECT c.bom_ref, c.component_name, c.component_type, c.version,
                   c.purl, s.sha256
            FROM live.sbom_components c
            JOIN live.snapshots s ON s.source_name = 'cyclonedx_dependencies'
            ORDER BY c.bom_ref
        ''')
        components = cur.fetchall()
        cur.execute('SELECT parent_ref, child_ref FROM live.sbom_edges ORDER BY 1,2')
        dependencies = cur.fetchall()

nodes = [
    {'id': 'sbom:' + ref, 'type': typ or 'component', 'name': name,
     'version': version, 'purl': purl, 'source_sha256': sha}
    for ref, name, typ, version, purl, sha in components
]
ids = {node['id'] for node in nodes}
source_hash = components[0][5] if components else None
edges = [
    {'source': 'sbom:' + parent, 'relation': 'DEPENDS_ON',
     'target': 'sbom:' + child, 'evidence_sha256': source_hash}
    for parent, child in dependencies
]
missing = [(e['source'], e['target']) for e in edges
           if e['source'] not in ids or e['target'] not in ids]
if missing:
    raise ValueError(f'Graph has dangling edges: {missing}')
for kind, payload in [('nodes', nodes), ('edges', edges)]:
    path = OUT / f'pg_graph_{kind}_live.json'
    path.write_text(json.dumps(payload, indent=2) + '\n')
    print(f'{path}: {len(payload)} entries')
print('PASS: all graph endpoints resolve; no unverified vulnerability edges emitted')
