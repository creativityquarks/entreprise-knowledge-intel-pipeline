import hashlib
import json
import os
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'data' / 'raw'
manifest = json.loads((RAW / 'live_manifest.json').read_text())


def file_for(r):
    raw = (RAW / (r['name'] + '.json')).read_bytes()
    if hashlib.sha256(raw).hexdigest() != r['sha256']:
        raise ValueError('SHA-256 mismatch: ' + r['name'])
    return json.loads(raw)


with psycopg.connect(os.environ['DATABASE_URL']) as conn:
    with conn.cursor() as cur:
        # REPLACE only this disposable lab schema, never raw files or lab fixtures.
        cur.execute('TRUNCATE live.advisory_aliases,live.sbom_edges, '
                    'live.sbom_components,live.osv_affected,live.snapshots CASCADE')
        docs = {}
        for r in manifest:
            if r['status'] != 'downloaded':
                continue
            obj = file_for(r)
            docs[r['name']] = obj
            cur.execute('INSERT INTO live.snapshots VALUES (%s,%s,%s,%s,%s,%s)',
                        (r['name'],r['url'],r['retrieved_utc'],r['sha256'],
                         r['bytes'],Jsonb(obj)))

        osv = docs['osv_log4shell']
        for i,a in enumerate(osv.get('affected', [])):
            p=a.get('package') or {}
            cur.execute('INSERT INTO live.osv_affected VALUES '
                        '(%s,%s,%s,%s,%s,%s,%s)',
                        ('osv_log4shell',osv['id'],i,p.get('ecosystem'),
                         p.get('name'),Jsonb(a.get('ranges',[])),
                         Jsonb(a.get('versions',[]))))

        bom=docs['cyclonedx_dependencies']
        if bom.get('bomFormat') != 'CycloneDX':
            raise ValueError('Not a CycloneDX document')
        root=bom.get('metadata',{}).get('component')
        components=([root] if root and root.get('bom-ref') else [])+bom.get('components',[])
        refs=[c['bom-ref'] for c in components]
        if len(refs)!=len(set(refs)):
            raise ValueError('Duplicate bom-ref')
        for c in components:
            cur.execute('INSERT INTO live.sbom_components VALUES '
                        '(%s,%s,%s,%s,%s,%s)',
                        (c['bom-ref'],c.get('name',''),c.get('group'),
                         c.get('version'),c.get('purl'),c.get('type')))
        for d in bom.get('dependencies',[]):
            if d['ref'] not in refs:
                raise ValueError('Unresolved dependency parent: '+d['ref'])
            for child in d.get('dependsOn',[]):
                if child not in refs:
                    raise ValueError('Unresolved dependency child: '+child)
                cur.execute('INSERT INTO live.sbom_edges VALUES (%s,%s)',
                            (d['ref'],child))

        gh=docs['github_log4shell']
        if gh.get('cve_id') and gh.get('ghsa_id'):
            cur.execute('INSERT INTO live.advisory_aliases VALUES (%s,%s,%s)',
                        ('github_log4shell',gh['cve_id'],gh['ghsa_id']))
        kev=docs['cisa_kev']
        for v in kev.get('vulnerabilities',[]):
            if v.get('cveID') == osv['id']:
                cur.execute('INSERT INTO live.advisory_aliases VALUES (%s,%s,%s)',
                            ('cisa_kev',v['cveID'],'CISA-KEV'))

print('Real-source JSON normalized into live.*')
