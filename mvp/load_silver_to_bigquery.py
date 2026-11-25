"""Load eight Silver tables atomically through staging and keyed BigQuery MERGE.

Run with one writer per dataset. No destructive migration or local checkpoint
controls whether a row is loaded. The current query bridge is replaced as a
unit, including the deletion of stale findings when a new query has no matches.
"""
import argparse
import uuid
from datetime import datetime, timedelta, timezone


from config import settings
from build_silver import KEYS, main as build_silver
from schema_validation import read_schema_contracts, validate_bigquery_schemas
from storage import ROOT, atomic_write, json_bytes, utc_now


def setup(client, project, dataset, location, contracts):
    """Create missing tables only, then fail closed on deployed schema drift."""
    from google.cloud import bigquery
    obj = bigquery.Dataset(f'{project}.{dataset}')
    obj.location = location
    actual = client.create_dataset(obj, exists_ok=True)
    if actual.location.upper() != location.upper():
        raise ValueError('Dataset location mismatch')
    for path in sorted((ROOT/'sql').glob('*.sql')):
        ddl = path.read_text().replace('{{PROJECT_ID}}', project).replace('{{DATASET}}', dataset)
        client.query(ddl, location=location).result()
    validate_bigquery_schemas(client, project, dataset, contracts)


def equality(keys, left='T', right='S'):
    return ' AND '.join(f'{left}.`{key}` = {right}.`{key}`' for key in keys)


def insert_clause(columns):
    return '(' + ', '.join(f'`{c}`' for c in columns) + ') VALUES (' + ', '.join(f'S.`{c}`' for c in columns) + ')'


def transaction_sql(prefix, stages, contracts):
    """Generate one transaction for facts and the latest component query bridge."""
    target = lambda name: f'`{prefix}.{name}`'
    stage = lambda name: f'`{stages[name]}`'
    statements = ['BEGIN TRANSACTION;']
    for name, keys in KEYS.items():
        group = ', '.join(f'`{k}`' for k in keys)
        statements.append(f"SELECT IF(COUNT(*) = 0, TRUE, ERROR('Existing duplicate keys: {name}')) AS keys_valid FROM (SELECT 1 FROM {target(name)} GROUP BY {group} HAVING COUNT(*) > 1);")
    for name, keys in KEYS.items():
        if name in ('component_queries', 'component_findings'):
            continue
        cols = [f.name for f in contracts[name]]
        statements.append(f'MERGE {target(name)} T USING {stage(name)} S ON {equality(keys)} '
                          f'WHEN NOT MATCHED THEN INSERT {insert_clause(cols)};')
    q, f = 'component_queries', 'component_findings'
    qkeys = KEYS[q]
    # Reject older observations. Equal timestamps are replayable for deterministic fixtures.
    statements.append(f'''DELETE FROM {target(f)} F WHERE STRUCT(F.source_sha256, F.bom_ref) IN (
      SELECT AS STRUCT S.source_sha256, S.bom_ref FROM {stage(q)} S LEFT JOIN {target(q)} T ON {equality(qkeys)}
      WHERE T.source_sha256 IS NULL OR S.queried_at >= T.queried_at);''')
    qcols = [field.name for field in contracts[q]]
    updates = ', '.join(f'`{c}` = S.`{c}`' for c in qcols if c not in qkeys)
    statements.append(f'MERGE {target(q)} T USING {stage(q)} S ON {equality(qkeys)} '
                      f'WHEN MATCHED AND S.queried_at >= T.queried_at THEN UPDATE SET {updates} '
                      f'WHEN NOT MATCHED THEN INSERT {insert_clause(qcols)};')
    fcols = [field.name for field in contracts[f]]
    select = ', '.join(f'F.`{c}`' for c in fcols)
    statements.append(f'''MERGE {target(f)} T USING (
      SELECT {select} FROM {stage(f)} F JOIN {stage(q)} S ON {equality(qkeys, 'F', 'S')}
      JOIN {target(q)} Q ON {equality(qkeys, 'Q', 'S')}
      WHERE Q.queried_at = S.queried_at AND Q.status = 'SUCCESS'
        AND Q.osv_query_sha256 = F.osv_query_sha256
      ) S ON {equality(KEYS[f])} WHEN NOT MATCHED THEN INSERT {insert_clause(fcols)};''')
    statements.append('COMMIT TRANSACTION;')
    return '\n'.join(statements)


def main(demo=False):
    from google.cloud import bigquery
    project, dataset, _, location = settings(demo)
    contracts = read_schema_contracts(ROOT/'sql')
    frames = build_silver(demo=demo)
    prefix = f'{project}.{dataset}'
    client = bigquery.Client(project=project)
    setup(client, project, dataset, location, contracts)
    run = uuid.uuid4().hex
    stages = {}
    try:
        for name, frame in frames.items():
            stage_id = f'{prefix}._stage_{name}_{run}'
            schema = client.get_table(f'{prefix}.{name}').schema
            stage = bigquery.Table(stage_id, schema=schema)
            stage.expires = datetime.now(timezone.utc) + timedelta(days=1)
            client.create_table(stage)
            stages[name] = stage_id
            if not frame.empty:
                config = bigquery.LoadJobConfig(schema=schema, write_disposition='WRITE_EMPTY', create_disposition='CREATE_NEVER')
                client.load_table_from_dataframe(frame, stage_id, job_config=config, location=location).result()
        job = client.query(transaction_sql(prefix, stages, contracts), location=location)
        job.result()
        # Audit only, not a skip checkpoint. A lost audit file cannot cause duplicates.
        data_dir = ROOT/'data'/ 'demo' if demo else ROOT/'data'
        atomic_write(data_dir/'metadata'/'loads'/f'{run}.json', json_bytes({
            'destination': prefix, 'job_id': job.job_id, 'committed_at': utc_now(),
            'staged_rows': {name: len(frame) for name, frame in frames.items()}}))
        print(f'Committed eight Silver tables: {prefix}')
    finally:
        for stage_id in stages.values():
            try:
                client.delete_table(stage_id, not_found_ok=True)
            except Exception as exc:
                print(f'Staging cleanup failed; expiry will remove {stage_id}: {exc}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo', action='store_true')
    main(demo=parser.parse_args().demo)
