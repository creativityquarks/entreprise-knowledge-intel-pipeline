import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FIX=ROOT/'data'/'fixtures'


def test_inventory_references_resolve():
    bom=json.loads((FIX/'inventory_run1.json').read_text())
    assert bom['bomFormat']=='CycloneDX'
    comps=[bom['metadata']['component']]+bom['components']
    refs={c['bom-ref'] for c in comps}
    assert len(refs)==len(comps)
    for edge in bom['dependencies']:
        assert edge['ref'] in refs
        assert set(edge.get('dependsOn',[])) <= refs


def test_fixture_package_matches_osv():
    bom=json.loads((FIX/'inventory_run1.json').read_text())
    osv=json.loads((FIX/'osv_log4shell.json').read_text())
    c=next(c for c in bom['components'] if c['name']=='log4j-core')
    package=next(a['package'] for a in osv['affected']
                 if a['package']['ecosystem']=='Maven')
    assert c['group']+':'+c['name']==package['name']
