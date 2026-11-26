"""Coordinate the supplied fetch_v2 provider/storage/manifest/query architecture."""
import argparse
import json
import re
import uuid
from component_identity import inventory, maven_request
from schema_validation import validate_raw_schema
from .providers.sbom import read_input, provenance
from .providers.osv import get_vuln_api_url
from .http import http
from .osv_query import capture_queries
from .manifest import save_run_manifest
from .storage import ROOT, json_bytes, read_snapshot, snapshot, utc_now

FIXTURES = ROOT / 'fixtures' / 'snapshots'

def live(data_dir, inputs, manifest):
    pending = []
    for app, location in inputs:
        try:
            body = read_input(location)
            meta = provenance(location, body, app)
            root, components = inventory(json.loads(body))
            if len(components) < 2:
                raise ValueError('No dependency components; inventory not assessable')
            entry = snapshot(data_dir, f'sbom_{app}', body)
            manifest['sboms'].append(dict(entry, application_id=app, retrieved_at=utc_now(), source=str(location), provenance=meta))
            for ref, comp in components.items():
                if ref == root:
                    continue
                request = maven_request(comp)
                row = {'sbom_sha256': entry['sha256'], 'bom_ref': ref, 'request': request,
                       'component_version': comp.get('version'), 'queried_at': utc_now()}
                if request is None:
                    manifest['queries'].append(dict(row, status='SKIPPED', error='Unsupported or ambiguous Maven identity'))
                else:
                    pending.append(row)
        except Exception as exc:
            manifest['errors'].append({'source': app, 'error': str(exc)})
    capture_queries(data_dir, pending, manifest)
    for osv_id in sorted(manifest.pop('_matched')):
        try:
            headers = {}
            raw = http(get_vuln_api_url(osv_id), metadata=headers)
            doc = json.loads(raw)
            validate_raw_schema(doc, 'osv')
            if doc['id'] != osv_id:
                raise ValueError('Advisory ID mismatch')
            manifest['advisories'].append(dict(snapshot(data_dir, 'osv_advisory', raw), retrieved_at=utc_now(), http=headers))
        except Exception as exc:
            manifest['errors'].append({'source': osv_id, 'error': str(exc)})


def demo(data_dir, manifest):
    """Import the attached reference's synthetic fixture, retaining provenance."""
    source = json.loads((FIXTURES/'metadata'/'ingestion_manifest.json').read_text())
    for entry in source['sboms']:
        read_snapshot(FIXTURES, entry)
        raw = (FIXTURES / entry['path']).read_bytes()
        manifest['sboms'].append(dict(snapshot(data_dir, 'sbom_'+entry['application_id'], raw),
            application_id=entry['application_id'], retrieved_at=source['retrieved_at']))
    for row in source['osv_queries']:
        response = read_snapshot(FIXTURES, row)
        entry = snapshot(data_dir, 'osv_queries', (FIXTURES/row['path']).read_bytes())
        manifest['queries'].append({**{k: row[k] for k in ('sbom_sha256','bom_ref','request','queried_at','status')},
                                    'evidence': entry})
        for vuln in response.get('vulns', []):
            manifest['advisories'].append(dict(snapshot(data_dir, 'osv_advisory', json_bytes(vuln)),
                retrieved_at=row['queried_at']))
    manifest.pop('_matched')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo', action='store_true', help='Import synthetic offline fixtures into data/demo')
    parser.add_argument('--sbom', action='append', default=[], metavar='APP=LOCAL_BOM_PATH')
    parser.add_argument('--generated', action='store_true', help='Use successful inventories from data/inventories')
    args = parser.parse_args()
    missing_generated = []
    if args.generated:
        if args.demo or args.sbom:
            parser.error('--generated cannot be combined with --demo or --sbom')
        # Use the curated registry, not an arbitrary directory glob; explicitly
        # record planned releases whose genuine inventory is missing.
        apps = json.loads((ROOT/'applications.json').read_text())
        for app in apps:
            for tag in app['releases']:
                path = ROOT/'data'/'inventories'/app['application_id']/tag/'bom.json'
                if path.is_file() and path.with_suffix('.provenance.json').is_file():
                    args.sbom.append(app['application_id'] + '=' + str(path))
                else:
                    missing_generated.append({'source':app['application_id'], 'release_tag':tag,
                        'error':'No generated inventory; release not assessed'})
        if not args.sbom:
            parser.error('No generated inventories; run generate_sboms.py first')
    if args.demo == bool(args.sbom):
        parser.error('Choose either --demo or one or more --sbom APP=LOCAL_BOM_PATH')
    inputs = []
    for value in args.sbom:
        app, sep, location = value.partition('=')
        if not sep or not re.fullmatch(r'[A-Za-z0-9_-]+', app) or not location or (app, location) in inputs:
            parser.error(f'Invalid or duplicate application input: {value}')
        inputs.append((app, location))
    data_dir = ROOT/'data'/ 'demo' if args.demo else ROOT/'data'
    run_id = utc_now().replace(':','').replace('+','_') + '_' + uuid.uuid4().hex[:8]
    manifest = {'format_version': 3, 'run_id': run_id, 'mode': 'SYNTHETIC_OFFLINE' if args.demo else 'LIVE',
                'started_at': utc_now(), 'sboms': [], 'advisories': [], 'queries': [], 'batches': [], 'errors': missing_generated, '_matched': set()}
    if args.demo:
        demo(data_dir, manifest)
    else:
        live(data_dir, inputs, manifest)
    manifest['finished_at'] = utc_now()

    # Ingestion exit-code contract:
    # 0  = SUCCESS: complete ingestion coverage.
    # 10 = PARTIAL: valid inventories but incomplete assessment.
    # 1  = FAILURE: no valid inventory ingested.
    # Preserve the actual QA status in the persisted manifest.
    failed = bool(
        manifest['errors']
        or any(q['status'] != 'SUCCESS' for q in manifest['queries'])
    )

    if not manifest['sboms']:
        manifest['status'] = 'FAILURE'
        exit_code = 1
    elif failed:
        manifest['status'] = 'PARTIAL'
        exit_code = 10
    else:
        manifest['status'] = 'SUCCESS'
        exit_code = 0

    path = save_run_manifest(data_dir, manifest)
    print(f'{manifest["status"]}: {path}')
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
