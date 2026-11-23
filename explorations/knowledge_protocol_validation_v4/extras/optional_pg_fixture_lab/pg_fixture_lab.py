import hashlib
import json
import os
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / 'data' / 'fixtures'
DB = os.environ['DATABASE_URL']


def load_file(name):
    raw = (FIX / name).read_bytes()
    return hashlib.sha256(raw).hexdigest(), json.loads(raw)


with psycopg.connect(DB) as conn:
    # Re-runnable: clear only our tutorial schema tables, not another team's data.
    with conn.cursor() as cur:
        cur.execute('TRUNCATE lab.exposure_results, lab.dependency_edges, '
                    'lab.components, lab.affected_packages, lab.snapshots CASCADE')
        digest, osv = load_file('osv_log4shell.json')
        cur.execute('INSERT INTO lab.snapshots '
                    '(snapshot_id,source_name,raw_document) VALUES (%s,%s,%s)',
                    (digest, 'fixture_osv', Jsonb(osv)))
        for i, entry in enumerate(osv.get('affected', [])):
            pkg = entry.get('package', {})
            cur.execute('INSERT INTO lab.affected_packages '
                        '(advisory_snapshot,cve_id,affected_index,ecosystem,package_name,ranges,explicit_versions) '
                        'VALUES (%s,%s,%s,%s,%s,%s,%s)',
                        (digest, osv['id'], i, pkg.get('ecosystem'), pkg.get('name'),
                         Jsonb(entry.get('ranges', [])), Jsonb(entry.get('versions', []))))

        for run_id in (1, 2):
            hash_, bom = load_file(f'inventory_run{run_id}.json')
            cur.execute('INSERT INTO lab.snapshots '
                        '(snapshot_id,source_name,raw_document) VALUES (%s,%s,%s)',
                        (hash_, f'fixture_inventory_run{run_id}', Jsonb(bom)))
            root = bom['metadata']['component']
            items = [root] + bom['components']
            refs = [c['bom-ref'] for c in items]
            if len(refs) != len(set(refs)):
                raise ValueError('Duplicate bom-ref')
            for c in items:
                group, name = c.get('group'), c['name']
                pkg = f'{group}:{name}' if group else None
                cur.execute('INSERT INTO lab.components VALUES '
                            '(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                            (run_id, c['bom-ref'], c.get('type'), name,
                             'Maven' if (c.get('purl') or '').startswith('pkg:maven/') else None,
                             pkg, c.get('version'), c.get('purl'), hash_))
            for d in bom.get('dependencies', []):
                if d['ref'] not in refs:
                    raise ValueError('Unknown parent')
                for child in d.get('dependsOn', []):
                    if child not in refs:
                        raise ValueError('Unknown child')
                    cur.execute('INSERT INTO lab.dependency_edges VALUES (%s,%s,%s,%s)',
                                (run_id, d['ref'], child, hash_))

print('Loaded fixture advisory and both inventory snapshots into PostgreSQL')
