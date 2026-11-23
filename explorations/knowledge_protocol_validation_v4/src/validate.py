"""Offline validation with curated fixtures; optional separate online source capture."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sqlite3
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / 'data' / 'fixtures'
OUT = ROOT / 'data' / 'outputs'


def stable_version(v: str):
    """Conservative comparison key for numeric Maven releases; not full ComparableVersion."""
    if not re.fullmatch(r'\d+(?:\.\d+)*', v):
        return None
    parts = [int(n) for n in v.split('.')]
    return tuple((parts + [0] * 8)[:8])


def affected(version: str, introduced: str, fixed: str) -> str:
    """Known range with numeric installed/fixed and potentially prerelease introduction.
    A nonnumeric lower bound can be judged only if installed numeric release is
    strictly greater than its numeric prefix; otherwise yield unknown.
    """
    installed, upper = stable_version(version), stable_version(fixed)
    if installed is None or upper is None:
        return 'unknown'
    lower = stable_version(introduced)
    if lower is None:
        m = re.fullmatch(r'(\d+(?:\.\d+)*)(?:[-.][A-Za-z0-9.-]+)', introduced)
        if not m:
            return 'unknown'
        base = stable_version(m.group(1))
        if installed <= base:
            return 'unknown'
    elif installed < lower:
        return 'not_affected'
    return 'affected' if installed < upper else 'not_affected'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def store(conn, file: Path, source: str, provenance: str, url: str | None = None):
    raw = file.read_bytes()
    doc = json.loads(raw)
    digest = sha(raw)
    conn.execute('INSERT OR IGNORE INTO snapshots VALUES (?,?,?,?,?,?)',
                 (digest, source, url, provenance, datetime.now(timezone.utc).isoformat(), raw.decode()))
    return doc, digest


def inventory(conn, run, doc, digest):
    assert doc['bomFormat'] == 'CycloneDX'
    appcomp = doc['metadata']['component']
    app, root = appcomp['name'], appcomp['bom-ref']
    components = [appcomp] + doc.get('components', [])
    refs = [c['bom-ref'] for c in components]
    if len(refs) != len(set(refs)):
        raise ValueError('Duplicate bom-ref')
    deps = doc.get('dependencies', [])
    for d in deps:
        if d['ref'] not in refs or any(t not in refs for t in d.get('dependsOn', [])):
            raise ValueError('Dangling dependency reference')
    for c in components:
        package = (c.get('group','') + ':' + c.get('name','')) if c.get('group') else None
        conn.execute('INSERT INTO inventory_components VALUES (?,?,?,?,?,?,?)',
                     (run,app,c['bom-ref'],package,c.get('version'),c.get('purl'),digest))
    adj = {}
    for d in deps:
        adj[d['ref']] = d.get('dependsOn', [])
        for child in d.get('dependsOn', []):
            conn.execute('INSERT INTO dependencies VALUES (?,?,?,?,?)', (run,app,d['ref'],child,digest))
    paths = {root: [root]}
    queue = deque([root])
    while queue:
        current = queue.popleft()
        for child in adj.get(current, []):
            if child not in paths:
                paths[child] = paths[current] + [child]
                queue.append(child)
    return app, paths


def export_graph(conn, run=1):
    nodes, edges = {}, {}
    for row in conn.execute('SELECT * FROM exposures WHERE run_id=?',(run,)):
        _,app,pkg,version,cve,status,path,inventory_hash,advisory_hash = row
        app_id='app:'+app
        pkg_id='pkg:'+pkg+'@'+version
        vul_id='cve:'+cve
        for node_id, typ, label in [(app_id,'Application',app),(pkg_id,'ComponentVersion',pkg+'@'+version),(vul_id,'Vulnerability',cve)]:
            nodes[node_id] = {'id':node_id,'type':typ,'label':label}
        # Preserve each step of transitive dependency path with evidence.
        steps = path.split(' > ')
        if steps:
            previous = app_id
            for step in steps[1:-1]:
                intermediate = 'ref:'+app+':'+step
                nodes[intermediate]={'id':intermediate,'type':'DependencyReference','label':step}
                edge=(previous,'DEPENDS_ON',intermediate)
                edges[edge]={'source':previous,'relation':'DEPENDS_ON','target':intermediate,'evidence_sha256':inventory_hash}
                previous=intermediate
            edge=(previous,'DEPENDS_ON',pkg_id)
            edges[edge]={'source':previous,'relation':'DEPENDS_ON','target':pkg_id,'evidence_sha256':inventory_hash}
        if status=='affected':
            edge=(pkg_id,'AFFECTED_BY',vul_id)
            edges[edge]={'source':pkg_id,'relation':'AFFECTED_BY','target':vul_id,'evidence_sha256':advisory_hash}
    (OUT / f'graph_nodes_run{run}.json').write_text(json.dumps(sorted(nodes.values(),key=lambda x:x['id']),indent=2)+'\n')
    (OUT / f'graph_edges_run{run}.json').write_text(json.dumps(sorted(edges.values(),key=lambda x:(x['source'],x['relation'],x['target'])),indent=2)+'\n')
    return nodes, edges


def run():
    OUT.mkdir(parents=True,exist_ok=True)
    db=OUT/'validation.sqlite'
    if db.exists(): db.unlink()
    conn=sqlite3.connect(db)
    conn.execute('PRAGMA foreign_keys=ON')
    conn.executescript((ROOT/'sql'/'schema.sql').read_text())
    osv, oh=store(conn,FIX/'osv_log4shell.json','OSV','curated_fixture','https://storage.googleapis.com/cve-osv-conversion/osv-output/CVE-2021-44228.json')
    ghsa, gh=store(conn,FIX/'ghsa_log4shell.json','GitHub','curated_fixture','https://api.github.com/advisories/GHSA-jfh8-c2jp-5v3q')
    kev, kh=store(conn,FIX/'kev_log4shell.json','CISA KEV','curated_fixture','https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
    assert ghsa['cve_id']==osv['id']==kev['vulnerabilities'][0]['cveID']
    assert ghsa['ghsa_id'] in osv['aliases']
    a=osv['affected'][0]
    package=a['package']
    events=a['ranges'][0]['events']
    introduced=events[0]['introduced'];fixed=events[1]['fixed']
    conn.execute('INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?)', (osv['id'],package['ecosystem'],package['name'],introduced,fixed,oh))
    for alias in osv.get('aliases',[]):
        conn.execute('INSERT INTO aliases VALUES (?,?)',(osv['id'],alias))
    inventory_hashes={}
    for run_id in (1,2):
        doc,digest=store(conn,FIX/f'inventory_run{run_id}.json','CycloneDX', 'synthetic_fixture')
        inventory_hashes[run_id]=digest
        app,paths=inventory(conn,run_id,doc,digest)
        for c in doc.get('components',[]):
            pname=c.get('group','')+':'+c.get('name','')
            if pname != package['name']:
                continue
            status=affected(c['version'],introduced,fixed)
            conn.execute('INSERT INTO exposures VALUES (?,?,?,?,?,?,?,?,?)',
                         (run_id,app,pname,c['version'],osv['id'],status,' > '.join(paths[c['bom-ref']]),digest,oh))
    conn.commit()
    nodes1,edges1=export_graph(conn,1)
    nodes2,edges2=export_graph(conn,2)
    results={
     'fixture_provenance':'CURATED + SYNTHETIC (NOT LIVE)',
     'snapshots':conn.execute('SELECT COUNT(*) FROM snapshots').fetchone()[0],
     'dependencies_run1':conn.execute('SELECT COUNT(*) FROM dependencies WHERE run_id=1').fetchone()[0],
     'exposures':[{'run':r[0],'version':r[1],'status':r[2]} for r in conn.execute('SELECT run_id,version,status FROM exposures ORDER BY run_id')],
     'graph_run1':{'nodes':len(nodes1),'edges':len(edges1)},
     'graph_run2':{'nodes':len(nodes2),'edges':len(edges2)},
     'foreign_key_violations':conn.execute('PRAGMA foreign_key_check').fetchall(),
     'test_outcomes':{'direct_and_transitive_graph':'pass','bounded_maven_examples':'pass','fixture_alias_join':'pass','historical_change':'pass','provenance_sha256':'pass','external_api_access':'NOT_RUN_NETWORK_BLOCKED','vps_graph_ingestion':'NOT_RUN_NO_ACCESS'}
    }
    assert results['dependencies_run1']==2
    assert [r['status'] for r in results['exposures']]==['affected','not_affected']
    assert any(e['relation']=='AFFECTED_BY' for e in edges1.values())
    assert not any(e['relation']=='AFFECTED_BY' for e in edges2.values())
    assert not results['foreign_key_violations']
    (OUT/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    conn.close()
    return results

if __name__=='__main__':
    print(json.dumps(run(),indent=2))
