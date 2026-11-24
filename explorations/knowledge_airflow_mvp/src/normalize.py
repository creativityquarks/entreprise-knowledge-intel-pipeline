"""Airflow task 2: GCS raw -> validated BigQuery Silver with idempotent MERGE."""
import argparse
import json
import os
from urllib.parse import urlsplit

from google.cloud import bigquery, storage
from core import run_key, sha256, validate_sbom

TABLES = (
    'source_snapshots','ingestion_runs',
    'applications','sboms','sbom_components','sbom_dependencies',
    'vulnerabilities','affected_packages','affected_version_events','component_findings'
)


def main(run_id):
    project = os.environ['GCP_PROJECT']
    bucket_name = os.environ['BRONZE_BUCKET']
    bucket = storage.Client(project=project).bucket(bucket_name)
    bq = bigquery.Client(project=project, location='EU')
    manifest_name = f'metadata/runs/{run_key(run_id)}.json'
    manifest = json.loads(bucket.blob(manifest_name).download_as_bytes())
    raw_docs = {}
    hashes = {}
    uris = {}
    for record in manifest['records']:
        uri = record['gcs_uri']
        path = urlsplit(uri).path.lstrip('/')
        raw = bucket.blob(path).download_as_bytes()
        if sha256(raw) != record['sha256']:
            raise ValueError(f"Hash mismatch: {record['source']}")
        raw_docs[record['source']] = json.loads(raw)
        hashes[record['source']] = record['sha256']
        uris[record['source']] = uri

    records = {table: [] for table in TABLES}
    for item in manifest['records']:
        records['source_snapshots'].append({
            'row_key':f"{item['source']}|{item['sha256']}",
            'source_name':item['source'],'sha256':item['sha256'],
            'source_url':item['source_url'],'gcs_uri':item['gcs_uri'],
            'size_bytes':item['bytes']})
        records['ingestion_runs'].append({
            'row_key':f"{run_key(run_id)}|{item['source']}",
            'run_id':run_id,'source_name':item['source'],
            'sha256':item['sha256'],'retrieved_at':item['retrieved_at'],
            'storage_status':item['storage_status'],'gcs_uri':item['gcs_uri']})
    component_to_apps = {}  # (package_name, version) -> (app_id, sbom_sha, ref, name)...

    for app_id in ('billing', 'analytics'):
        source = f'sbom_{app_id}'
        sha = hashes[source]
        bom = raw_docs[source]
        components, edges = validate_sbom(bom)
        root = bom['metadata']['component']
        records['applications'].append({
            'row_key': app_id,'application_id': app_id,'application_name':root['name']})
        records['sboms'].append({
            'row_key': sha,'source_sha256':sha,'application_id':app_id,
            'root_bom_ref':root['bom-ref'],'source_uri':uris[source]})
        for c in components:
            package_name = (f"{c['group']}:{c['name']}" if c.get('group') else None)
            records['sbom_components'].append({
                'row_key':f"{sha}|{c['bom-ref']}",'source_sha256':sha,
                'bom_ref':c['bom-ref'],'component_name':c.get('name'),
                'component_group':c.get('group'),'component_version':c.get('version'),
                'package_name':package_name,'purl':c.get('purl'),
                'is_root':c['bom-ref']==root['bom-ref']})
            if package_name and (c.get('purl') or '').startswith('pkg:maven/'):
                component_to_apps.setdefault((package_name,c.get('version')),[]).append(
                    (app_id,sha,c['bom-ref'],c['name']))
        for edge in edges:
            records['sbom_dependencies'].append({
                'row_key':f"{sha}|{edge['parent']}|{edge['child']}",
                'source_sha256':sha,'parent_bom_ref':edge['parent'],
                'child_bom_ref':edge['child']})

    doc = raw_docs['osv_advisory']
    adv_sha = hashes['osv_advisory']
    if not isinstance(doc.get('affected', []), list):
        raise ValueError('Invalid OSV affected list')
    vuln_id = doc['id']
    records['vulnerabilities'].append({
        'row_key':f'{adv_sha}|{vuln_id}', 'source_sha256':adv_sha,
        'vulnerability_id':vuln_id, 'summary':doc.get('summary'),
        'published_at':doc.get('published'), 'modified_at':doc.get('modified'),
        'advisory_url':f'https://osv.dev/vulnerability/{vuln_id}'})
    for ai, affected in enumerate(doc.get('affected', [])):
        pkg = affected.get('package') or {}
        records['affected_packages'].append({
            'row_key':f'{adv_sha}|{ai}', 'source_sha256':adv_sha,
            'vulnerability_id':vuln_id,'affected_index':ai,
            'ecosystem':pkg.get('ecosystem'), 'package_name':pkg.get('name')})
        for ri, rng in enumerate(affected.get('ranges', [])):
            for ei, evt in enumerate(rng.get('events', [])):
                if len(evt)!=1:
                    raise ValueError('Malformed OSV version event')
                k,v=next(iter(evt.items()))
                if k not in {'introduced','fixed','last_affected','limit'}:
                    raise ValueError(f'Unexpected OSV version event type: {k}')
                records['affected_version_events'].append({
                    'row_key':f'{adv_sha}|{ai}|{ri}|{ei}', 'source_sha256':adv_sha,
                    'vulnerability_id':vuln_id,'affected_index':ai,'range_index':ri,
                    'event_index':ei,'range_type':rng.get('type'),
                    'event_type':k,'event_value':str(v)})

    batch = raw_docs['osv_batch']
    queries = manifest['queries']
    results = batch.get('results', [])
    if len(results) != len(queries):
        raise ValueError('OSV results do not correspond to queries')
    query_sha = hashes['osv_batch']
    for query, result in zip(queries, results):
        key=(query['package']['name'], query['version'])
        for vuln in result.get('vulns', []):
            osv_id = vuln['id']
            for app_id, sbom_sha, ref, name in component_to_apps.get(key, []):
                records['component_findings'].append({
                    'row_key':f'{sbom_sha}|{ref}|{osv_id}|{query_sha}',
                    'source_sha256':sbom_sha, 'application_id':app_id,
                    'bom_ref':ref,'component_name':name,'package_name':key[0],
                    'component_version':key[1],'vulnerability_id':osv_id,
                    'query_sha256':query_sha})

    # Each table uses a temporary load followed by a stable-key MERGE.
    # Re-running the same snapshot does not append duplicate Silver rows.
    for table, rows in records.items():
        if not rows:
            print(f'{table}: no rows')
            continue
        dataset = ('vulnerability_bronze' if table in ('source_snapshots','ingestion_runs')
                   else 'vulnerability_silver')
        dest = f'{project}.{dataset}.{table}'
        stage = f'{project}.{dataset}._stage_{table}'
        full_schema = bq.get_table(dest).schema
        source_schema = [col for col in full_schema if col.name != 'first_seen']
        job = bq.load_table_from_json(
            rows,stage,
            job_config=bigquery.LoadJobConfig(
                schema=source_schema,
                source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE,
            ),
            location='EU',
        )
        job.result()
        cols = [field.name for field in source_schema]
        col_list = ', '.join(f'`{col}`' for col in cols)
        select_list = ', '.join(f'S.`{col}`' for col in cols)
        sql = f'''MERGE `{dest}` T USING `{stage}` S
                  ON T.row_key=S.row_key
                  WHEN NOT MATCHED THEN INSERT ({col_list}) VALUES ({select_list})'''
        bq.query(sql, location='EU').result()
        print(f'{table}: processed {len(rows)} source rows')


if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--run-id',required=True)
    args=p.parse_args()
    try:
        main(args.run_id)
    except Exception as exc:
        # Raw snapshots remain untouched; the report enables investigation.
        from google.api_core.exceptions import PreconditionFailed
        bucket = storage.Client().bucket(os.environ['BRONZE_BUCKET'])
        path = f"quarantine/reports/{run_key(args.run_id)}.json"
        try:
            bucket.blob(path).upload_from_string(
                json.dumps({'run_id':args.run_id,'error':f'{type(exc).__name__}: {exc}'}),
                content_type='application/json',if_generation_match=0)
        except PreconditionFailed:
            pass
        raise

