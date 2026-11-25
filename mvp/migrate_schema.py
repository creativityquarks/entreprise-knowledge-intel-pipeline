"""Explicit, versioned, checksum-verified additive migrations for existing Silver.

Run with one writer, after backup/review. BigQuery permanent DDL is not atomic
across statements; migrations must be independently repeatable. No data rewrite
or implicit conversion of legacy arrays is attempted. Fresh datasets use DDL.
"""
import argparse
import hashlib
from config import ROOT,settings


def main(demo=False,apply=False):
    from google.cloud import bigquery
    from schema_validation import read_schema_contracts,validate_bigquery_schemas
    project,dataset,_,location=settings(demo)
    client=bigquery.Client(project=project)
    prefix=f'{project}.{dataset}'
    paths=sorted((ROOT/'migrations').glob('*.sql'))
    if not apply:
        for path in paths:
            print(path.name,hashlib.sha256(path.read_bytes()).hexdigest())
            print(path.read_text().replace('{{PROJECT_ID}}',project).replace('{{DATASET}}',dataset))
        print('Review the SQL; use --apply to execute against '+prefix)
        return
    # Fail closed on unexpected existing schema drift before touching DDL.
    contracts = read_schema_contracts(ROOT/'sql')
    new_fields = {'release_tag','repository_url','git_commit','commit_at','java_version','maven_version','generator_version','generated_at'}
    aliases = {'INTEGER':'INT64','BOOLEAN':'BOOL'}
    for table, fields in contracts.items():
        expected = {f.name:(f.type,f.mode) for f in fields}
        observed = {f.name:(aliases.get(f.field_type.upper(),f.field_type.upper()),(f.mode or 'NULLABLE').upper()) for f in client.get_table(f'{prefix}.{table}').schema}
        absent = set(expected)-set(observed)
        allowed = new_fields if table=='sboms' else set()
        if absent-allowed or any(k not in expected or expected[k]!=v for k,v in observed.items()):
            raise ValueError(f'Unexpected schema drift in {table}; review and migrate separately')
    ledger=f'{prefix}.schema_migrations'
    client.query(f'CREATE TABLE IF NOT EXISTS `{ledger}` (migration_id STRING NOT NULL, sha256 STRING NOT NULL, applied_at TIMESTAMP NOT NULL)',location=location).result()
    applied={}
    for row in client.query(f'SELECT migration_id,sha256 FROM `{ledger}`',location=location).result():
        if row.migration_id in applied:
            raise ValueError('Duplicate migration ledger entry')
        applied[row.migration_id]=row.sha256
    if set(applied)-{p.name for p in paths}:
        raise ValueError('Applied migration file missing from repository')
    for path in paths:
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if path.name in applied:
            if applied[path.name]!=digest:
                raise ValueError(f'Applied migration was modified: {path.name}')
            continue
        sql=path.read_text().replace('{{PROJECT_ID}}',project).replace('{{DATASET}}',dataset)
        client.query(sql,location=location).result()
        # This release has one additive migration, and the final DDL is its contract.
        validate_bigquery_schemas(client,project,dataset,contracts)
        config=bigquery.QueryJobConfig(query_parameters=[bigquery.ScalarQueryParameter('id','STRING',path.name),bigquery.ScalarQueryParameter('sha','STRING',digest)])
        client.query(f'INSERT INTO `{ledger}` VALUES (@id,@sha,CURRENT_TIMESTAMP())',job_config=config,location=location).result()
    validate_bigquery_schemas(client,project,dataset,read_schema_contracts(ROOT/'sql'))
    print('Silver schema validated after migration')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--demo',action='store_true'); p.add_argument('--apply',action='store_true')
    a=p.parse_args(); main(a.demo,a.apply)
