#!/usr/bin/env python3
"""Pedagogical knowledge pipeline: Python stdlib only; synthetic inventory and reduced advisory.

Run: python demo_v3.py --all | --step bronze|silver|gold|graph|validate | --reset
"""
import argparse
import hashlib
import json
import re
import shutil
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'output'
BRONZE = DATA / 'bronze'
DB = DATA / 'demo.sqlite'
PACKAGE = 'org.apache.logging.log4j:log4j-core'
CVE = 'CVE-2021-44228'

# This is a *reduced illustrative* OSV-shaped record, NOT the complete live advisory.
ADVISORY = {
    'id': CVE,
    'affected': [{'package': {'ecosystem': 'Maven', 'name': PACKAGE},
                  'ranges': [{'type': 'ECOSYSTEM', 'events': [
                      {'introduced': '2.0-beta9'}, {'fixed': '2.15.0'}]}]}],
    'references': [{'type': 'ADVISORY',
                    'url': 'https://logging.apache.org/log4j/2.x/security.html'}],
}


def inventory(application, version):
    """Tiny CycloneDX-shaped SBOM: one direct dependency, not a real enterprise SBOM."""
    return {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5',
        'metadata': {'component': {'type': 'application', 'name': application,
                                   'bom-ref': application}},
        'components': [{'type': 'library', 'bom-ref': 'library-1',
                        'group': 'org.apache.logging.log4j', 'name': 'log4j-core',
                        'version': version,
                        'purl': 'pkg:maven/org.apache.logging.log4j/log4j-core@' + version}],
        'dependencies': [{'ref': application, 'dependsOn': ['library-1']}],
    }


# Clear names: A = external advisory; B = Billing inventory; C = Analytics inventory.
# B changes from run 1 to run 2. C stays identical but is observed in both runs.
INPUTS = [('advisory', ADVISORY),
          ('billing_run1', inventory('Billing', '2.14.1')),
          ('analytics_run1', inventory('Analytics', '2.17.1')),
          ('billing_run2', inventory('Billing', '2.17.1')),
          ('analytics_run2', inventory('Analytics', '2.17.1'))]


def show(title, rows, headers):
    print('\n' + title)
    print(' | '.join(headers))
    for row in rows:
        print(' | '.join(str(v) for v in row))


def rows(db, sql, params=()):
    return db.execute(sql, params).fetchall()


def snapshot(name, obj):
    """Persist canonical bytes of a fixture. Live ingestion must save HTTP response bytes."""
    raw = json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')
    sha = hashlib.sha256(raw).hexdigest()
    filename = f'{name}-{sha}.json'
    dest = BRONZE / filename
    if dest.exists():
        assert dest.read_bytes() == raw, 'Snapshot integrity mismatch'
    else:
        dest.write_bytes(raw)
    return filename


def bronze():
    BRONZE.mkdir(parents=True, exist_ok=True)
    manifest = {name: snapshot(name.split("_run")[0], obj) for name, obj in INPUTS}
    (DATA / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    show('BRONZE — immutable fixture snapshots',
         [(k, v[:32] + '...') for k, v in manifest.items()],
         ['logical source', 'content-addressed filename'])
    print('Same Analytics bytes in both runs; separate logical snapshots, same content.')


def load(name, manifest):
    return json.loads((BRONZE / manifest[name]).read_bytes())


def affected(version, introduced, fixed):
    """Deliberately bounded comparator for the *single* demonstration range.

    Not a general Maven version parser. Unsupported cases raise rather than guessing.
    """
    if (introduced, fixed) != ('2.0-beta9', '2.15.0'):
        raise ValueError('Unsupported advisory range')
    if not re.fullmatch(r'2\.\d+\.\d+', version):
        raise ValueError('Unsupported release syntax')
    return tuple(map(int, version.split('.'))) < (2, 15, 0)


def silver():
    manifest = json.loads((DATA / 'manifest.json').read_text())
    if DB.exists():
        DB.unlink()  # Rebuild SQLite deterministically from preserved Bronze snapshots.
    with sqlite3.connect(DB) as db:
        db.executescript('''
        PRAGMA foreign_keys=ON;
        CREATE TABLE vulnerabilities (
            cve TEXT PRIMARY KEY, ecosystem TEXT NOT NULL, package TEXT NOT NULL,
            introduced TEXT NOT NULL, fixed TEXT NOT NULL, evidence TEXT NOT NULL);
        CREATE TABLE components (
            run_id INTEGER NOT NULL, app TEXT NOT NULL, ecosystem TEXT NOT NULL,
            package TEXT NOT NULL, version TEXT NOT NULL, evidence TEXT NOT NULL,
            PRIMARY KEY(run_id,app,package,version));
        CREATE TABLE source_candidates (
            url TEXT PRIMARY KEY, discovered_via TEXT NOT NULL, status TEXT NOT NULL);
        ''')
        advisory = load('advisory', manifest)
        for item in advisory['affected']:
            package = item['package']
            for range_ in item['ranges']:
                start, end = range_['events']
                db.execute('INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?)',
                           (advisory['id'], package['ecosystem'], package['name'],
                            start['introduced'], end['fixed'], manifest['advisory']))
        for ref in advisory.get('references', []):
            db.execute('INSERT OR IGNORE INTO source_candidates VALUES (?,?,?)',
                       (ref['url'], advisory['id'], 'candidate'))
        for run_id in (1, 2):
            for app, key in [('Billing', f'billing_run{run_id}'),
                             ('Analytics', f'analytics_run{run_id}')]:
                doc = load(key, manifest)
                root = doc['metadata']['component']['bom-ref']
                direct = next(d['dependsOn'] for d in doc['dependencies'] if d['ref'] == root)
                for c in doc['components']:
                    if c['bom-ref'] in direct:
                        db.execute('INSERT INTO components VALUES (?,?,?,?,?,?)',
                                   (run_id, app, 'Maven', c['group'] + ':' + c['name'],
                                    c['version'], manifest[key]))
        show('SILVER — normalized components', rows(db, '''
             SELECT run_id,app,version FROM components ORDER BY run_id,app'''),
             ['run', 'application', 'installed version'])
        show('SILVER — discovered source references',
             rows(db, 'SELECT url,status FROM source_candidates'), ['url', 'status'])


JOIN_SQL = '''
SELECT c.run_id,c.app,c.package,c.version,v.cve,v.introduced,v.fixed,
       v.evidence,c.evidence
FROM components AS c JOIN vulnerabilities AS v
  ON c.ecosystem=v.ecosystem AND c.package=v.package
ORDER BY c.run_id,c.app
'''


def gold():
    with sqlite3.connect(DB) as db:
        db.executescript('''
        DROP TABLE IF EXISTS exposure;
        CREATE TABLE exposure (
            run_id INTEGER, app TEXT, package TEXT, version TEXT, cve TEXT,
            affected INTEGER CHECK(affected IN (0,1)),
            advisory_evidence TEXT, inventory_evidence TEXT,
            PRIMARY KEY(run_id,app,package,version,cve));
        ''')
        for run_id, app, pkg, ver, cve, low, high, adv, inv in rows(db, JOIN_SQL):
            db.execute('INSERT INTO exposure VALUES (?,?,?,?,?,?,?,?)',
                       (run_id, app, pkg, ver, cve, int(affected(ver, low, high)), adv, inv))
        db.executescript('''
        DROP VIEW IF EXISTS current_exposure;
        CREATE VIEW current_exposure AS
          SELECT * FROM exposure WHERE run_id=(SELECT MAX(run_id) FROM exposure);
        DROP VIEW IF EXISTS exposure_history;
        CREATE VIEW exposure_history AS SELECT * FROM exposure;
        DROP VIEW IF EXISTS exposure_changes;
        CREATE VIEW exposure_changes AS
          SELECT old.app,old.cve,old.version AS old_version,
                 new.version AS new_version,old.affected AS old_affected,
                 new.affected AS new_affected
          FROM exposure old JOIN exposure new
            ON old.app=new.app AND old.package=new.package AND old.cve=new.cve
          WHERE old.run_id=1 AND new.run_id=2
            AND (old.version<>new.version OR old.affected<>new.affected);
        DROP VIEW IF EXISTS dashboard_summary;
        CREATE VIEW dashboard_summary AS
          SELECT run_id,COUNT(DISTINCT app) AS applications,
                 SUM(affected) AS affected_app_package_cve_rows
          FROM exposure GROUP BY run_id;
        DROP VIEW IF EXISTS evidence_audit;
        CREATE VIEW evidence_audit AS
          SELECT run_id,app,cve,advisory_evidence,inventory_evidence FROM exposure;
        ''')
        show('GOLD — dashboard summary', rows(db, 'SELECT * FROM dashboard_summary'),
             ['run', 'applications', 'affected matches'])
        show('GOLD — change history', rows(db, 'SELECT * FROM exposure_changes'),
             ['app', 'CVE', 'before', 'after', 'affected before', 'affected after'])
        show('GOLD — current mart',
             rows(db, 'SELECT app,version,cve,affected FROM current_exposure ORDER BY app'),
             ['application', 'version', 'CVE', 'affected'])


def graph_for_run(db, run_id):
    """Materialize graph-ready data from the Gold mart, not from LLM inference."""
    records = rows(db, '''SELECT app,package,version,cve,affected,
                                 advisory_evidence,inventory_evidence
                          FROM exposure WHERE run_id=?''', (run_id,))
    nodes, edges = {}, {}
    for app, pkg, ver, cve, is_affected, adv, inv in records:
        app_id, pkg_id, cve_id = 'app:' + app, 'pkg:' + pkg + '@' + ver, 'cve:' + cve
        for node in ({'id': app_id, 'type': 'Application', 'name': app},
                     {'id': pkg_id, 'type': 'ComponentVersion', 'name': pkg + '@' + ver},
                     {'id': cve_id, 'type': 'Vulnerability', 'name': cve}):
            nodes[node['id']] = node
        dep = {'source': app_id, 'type': 'DEPENDS_ON', 'target': pkg_id, 'evidence': inv}
        edges[(dep['source'], dep['type'], dep['target'])] = dep
        if is_affected:
            aff = {'source': pkg_id, 'type': 'AFFECTED_BY', 'target': cve_id, 'evidence': adv}
            edges[(aff['source'], aff['type'], aff['target'])] = aff
    return nodes, edges


def graph():
    with sqlite3.connect(DB) as db:
        previous_nodes, previous_edges = graph_for_run(db, 1)
        current_nodes, current_edges = graph_for_run(db, 2)
    # This delta is what the team's graph synchronization task would send to the VPS API.
    def changes(old, new):
        return {'upsert': [new[k] for k in sorted(new) if k not in old or new[k] != old[k]],
                'delete': [old[k] for k in sorted(old) if k not in new]}
    payloads = {
        'graph_run1.json': {'nodes': list(previous_nodes.values()), 'edges': list(previous_edges.values())},
        'graph_run2.json': {'nodes': list(current_nodes.values()), 'edges': list(current_edges.values())},
        'graph_delta.json': {'nodes': changes(previous_nodes, current_nodes),
                             'edges': changes(previous_edges, current_edges)},
    }
    for filename, payload in payloads.items():
        (DATA / filename).write_text(json.dumps(payload, indent=2))
    delta = payloads['graph_delta.json']
    show('GRAPH — proposed synchronization change set',
         [(kind, len(delta[kind]['upsert']), len(delta[kind]['delete'])) for kind in ('nodes', 'edges')],
         ['object', 'upserts', 'deletions'])
    print('Graph API calls are NOT executed. JSON is ready for a future integration.')


def validate():
    manifest = json.loads((DATA / 'manifest.json').read_text())
    for filename in manifest.values():
        sha = filename.rsplit('-', 1)[-1].removesuffix('.json')
        assert hashlib.sha256((BRONZE / filename).read_bytes()).hexdigest() == sha
    assert affected('2.14.1', '2.0-beta9', '2.15.0')
    assert not affected('2.15.0', '2.0-beta9', '2.15.0')
    assert not affected('2.17.1', '2.0-beta9', '2.15.0')
    with sqlite3.connect(DB) as db:
        assert rows(db, 'SELECT run_id,app,affected FROM exposure ORDER BY run_id,app') == [
            (1, 'Analytics', 0), (1, 'Billing', 1),
            (2, 'Analytics', 0), (2, 'Billing', 0)]
        assert len(rows(db, 'SELECT * FROM exposure_changes')) == 1
        assert len(rows(db, 'SELECT * FROM source_candidates')) == 1
        assert all(a and b for a, b in rows(db,
            'SELECT advisory_evidence,inventory_evidence FROM evidence_audit'))
    delta = json.loads((DATA / 'graph_delta.json').read_text())
    assert len(delta['edges']['delete']) == 2  # Old Billing dependency and old exposure edge.
    assert len(delta['edges']['upsert']) == 1  # New Billing dependency.
    print('\nPASS — evidence hashes, SQL mart, version boundaries, history, source registry, graph delta')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--all', action='store_true', help='Run all five stages')
    action.add_argument('--step', choices=['bronze', 'silver', 'gold', 'graph', 'validate'])
    action.add_argument('--reset', action='store_true', help='Delete generated output; preserve script')
    args = parser.parse_args()
    if args.reset:
        if DATA.exists():
            shutil.rmtree(DATA)
        print('Deleted generated output/. Run --all to replay.')
        return
    stages = {'bronze': bronze, 'silver': silver, 'gold': gold,
              'graph': graph, 'validate': validate}
    if args.all:
        for func in stages.values():
            func()
    else:
        stages[args.step]()


if __name__ == '__main__':
    main()
