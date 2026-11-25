"""Build shortest dependency paths and run the translated dbt Gold models.

BFS visits each component once per inventory (O(V+E) traversal). Store only one
shortest path; no exponential enumeration of all simple paths. Execute with one
writer and no concurrent Silver load; dbt publishes each model separately.
"""
import argparse
from collections import defaultdict, deque
import subprocess
import uuid
from config import ROOT, settings


def shortest_paths(sbom, root, names, edges):
    """Deterministic shortest paths with cycle handling and endpoint checks."""
    if root not in names:
        raise ValueError(f'{sbom}: root missing')
    children = defaultdict(set)
    for parent, child in edges:
        if parent not in names or child not in names:
            raise ValueError(f'{sbom}: unresolved edge')
        children[parent].add(child)
    queue = deque([(root,names[root],0)])
    visited = {root}
    rows = []
    while queue:
        ref,path,hops = queue.popleft()
        rows.append({'sbom_sha256':sbom,'bom_ref':ref,'path_text':path,'hops':hops})
        for child in sorted(children[ref]):
            if child not in visited:
                visited.add(child)
                queue.append((child,path+' > '+names[child],hops+1))
    return rows


def prepare_paths(client, project, silver, gold, location):
    from google.cloud import bigquery
    prefix = f'{project}.{silver}'
    def read(table, columns):
        return client.query(f'SELECT {columns} FROM `{prefix}.{table}`',location=location).result()
    names, edges = defaultdict(dict), defaultdict(list)
    for row in read('sbom_components','source_sha256,bom_ref,name,version'):
        if row.bom_ref is None or row.bom_ref in names[row.source_sha256]:
            raise ValueError('Missing or duplicate component reference')
        names[row.source_sha256][row.bom_ref] = row.name + ('@'+row.version if row.version else '')
    for row in read('sbom_dependencies','source_sha256,parent_bom_ref,child_bom_ref'):
        edges[row.source_sha256].append((row.parent_bom_ref,row.child_bom_ref))
    rows = []
    for row in read('sboms','source_sha256,root_component_ref'):
        rows.extend(shortest_paths(row.source_sha256,row.root_component_ref,names[row.source_sha256],edges[row.source_sha256]))
    ds = bigquery.Dataset(f'{project}.{gold}'); ds.location=location
    actual = client.create_dataset(ds,exists_ok=True)
    if actual.location.upper()!=location.upper():
        raise ValueError('Gold dataset location mismatch')
    schema = [bigquery.SchemaField(k,t,mode='REQUIRED') for k,t in [('sbom_sha256','STRING'),('bom_ref','STRING'),('path_text','STRING'),('hops','INTEGER')]]
    if not rows:
        raise ValueError('No valid Silver inventories; Gold cannot be published')
    # An atomic load replaces only this derived table, never a Silver fact table.
    job = client.load_table_from_json(rows,f'{project}.{gold}.component_paths',
        job_config=bigquery.LoadJobConfig(schema=schema,write_disposition='WRITE_TRUNCATE'),location=location)
    job.result()
    print(f'Published {len(rows)} shortest paths')


def mark_publication(client, project, gold, location, run_id, status):
    """Expose one publication status, so consumers never read a partial rebuild."""
    from google.cloud import bigquery
    config = bigquery.QueryJobConfig(query_parameters=[
        bigquery.ScalarQueryParameter('run_id','STRING',run_id),
        bigquery.ScalarQueryParameter('status','STRING',status)])
    client.query(f'CREATE OR REPLACE TABLE `{project}.{gold}.gold_publication` AS '
                 'SELECT @run_id AS run_id, @status AS status, CURRENT_TIMESTAMP() AS status_at',
                 job_config=config,location=location).result()


def main(demo=False):
    from google.cloud import bigquery
    project,silver,gold,location = settings(demo)
    client = bigquery.Client(project=project)
    ds = bigquery.Dataset(f'{project}.{gold}'); ds.location=location
    actual = client.create_dataset(ds,exists_ok=True)
    if actual.location.upper()!=location.upper():
        raise ValueError('Gold dataset location mismatch')
    run_id = uuid.uuid4().hex
    mark_publication(client,project,gold,location,run_id,'BUILDING')
    try:
        if not demo:
            # Never silently treat pre-v4/fixture inventory rows as real releases.
            invalid = client.query(f'''SELECT COUNT(*) AS n FROM `{project}.{silver}.sboms`
                WHERE release_tag IS NULL OR git_commit IS NULL OR repository_url IS NULL
                   OR commit_at IS NULL OR generated_at IS NULL''',location=location).result()
            if next(iter(invalid)).n:
                raise ValueError('Live Silver contains inventories without real release provenance; use a fresh dataset or explicitly reconcile them')
        prepare_paths(client,project,silver,gold,location)
        # Use the current venv's dbt executable, with .env loaded for dbt.
        executable = str(ROOT/'.venv'/'bin'/'dbt') if (ROOT/'.venv'/'bin'/'dbt').exists() else 'dbt'
        subprocess.run([executable,'build','--project-dir',str(ROOT/'gold'),'--profiles-dir',str(ROOT/'gold'/'profiles'),
                        '--target','demo' if demo else 'live'],check=True)
        mark_publication(client,project,gold,location,run_id,'SUCCESS')
    except Exception:
        mark_publication(client,project,gold,location,run_id,'FAILED')
        raise

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--demo',action='store_true')
    main(parser.parse_args().demo)
