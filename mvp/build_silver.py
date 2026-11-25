"""Offline Bronze replay into eight validated Silver DataFrames.

Replaying manifests is deliberate for the small MVP: BigQuery MERGE, not a
local skip list, provides the persistence boundary and retry safety.
"""
import argparse
import json
import os
from pathlib import Path

import pandas as pd
from component_identity import inventory, maven_request
from pipeline.ingestion.osv_query import result_ids
from schema_validation import read_schema_contracts, validate_raw_schema, normalize_and_validate_dataframes
from storage import ROOT, read_snapshot

SQL_DIR = ROOT / 'sql'
KEYS = {
    'sboms': ['source_sha256'],
    'sbom_components': ['source_sha256', 'component_index'],
    'sbom_dependencies': ['source_sha256', 'parent_bom_ref', 'child_bom_ref'],
    'vulnerabilities': ['osv_id', 'source_sha256'],
    'affected_packages': ['osv_id', 'source_sha256', 'affected_index'],
    'affected_version_events': ['osv_id', 'source_sha256', 'affected_index', 'range_index', 'event_index'],
    'component_queries': ['source_sha256', 'bom_ref'],
    'component_findings': ['source_sha256', 'bom_ref', 'vulnerability_id'],
}


def transform_osv(data, source_sha256, retrieved_at):
    """Preserve advisory identity, affected entries and ordered range events."""
    osv_id = data["id"]
    vulnerabilities = [{
        "osv_id": osv_id,
        "summary": data.get("summary"),
        "published_at": data.get("published"),
        "modified_at": data.get("modified"),
        "withdrawn_at": data.get("withdrawn"),
        "aliases": data.get("aliases", []),
        "source_sha256": source_sha256,
        "retrieved_at": retrieved_at,
    }]
    affected_packages = []
    affected_version_events = []
    for affected_index, affected in enumerate(data.get("affected", [])):
        package = affected.get("package", {})
        affected_packages.append({
            "osv_id": osv_id,
            "source_sha256": source_sha256,
            "affected_index": affected_index,
            "ecosystem": package.get("ecosystem"),
            "package_name": package.get("name"),
            "package_purl": package.get("purl"),
            "affected_versions": affected.get("versions", []),
        })
        for range_index, version_range in enumerate(affected.get("ranges", [])):
            for event_index, event in enumerate(version_range.get("events", [])):
                if len(event) != 1:
                    raise ValueError(f"Unexpected OSV event: {event}")
                event_type, event_value = next(iter(event.items()))
                affected_version_events.append({
                    "osv_id": osv_id,
                    "source_sha256": source_sha256,
                    "affected_index": affected_index,
                    "range_index": range_index,
                    "range_type": version_range.get("type"),
                    "event_index": event_index,
                    "event_type": event_type,
                    "event_value": event_value,
                })
    return {
        "vulnerabilities": pd.DataFrame(vulnerabilities),
        "affected_packages": pd.DataFrame(affected_packages),
        "affected_version_events": pd.DataFrame(affected_version_events),
    }


def transform_cyclonedx(data, source_sha256, application_id, retrieved_at):
    """Flatten SBOM inventory and dependsOn edges; retain root identity."""
    metadata = data.get("metadata", {})
    root_ref, refs = inventory(data)
    components = list(refs.values())
    root_component = refs[root_ref]
    sbom_id = application_id
    sboms = [{
        "sbom_id": sbom_id,
        "serial_number": data.get("serialNumber"),
        "spec_version": data.get("specVersion"),
        "version": data.get("version"),
        "metadata_timestamp": metadata.get("timestamp"),
        "root_component_ref": root_ref,
        "source_sha256": source_sha256,
        "retrieved_at": retrieved_at,
    }]
    sbom_components = []
    for component_index, component in enumerate(components):
        bom_ref = component.get("bom-ref")
        sbom_components.append({
            "sbom_id": sbom_id,
            "source_sha256": source_sha256,
            "bom_ref": bom_ref,
            "component_index": component_index,
            "name": component["name"],
            "group_name": component.get("group"),
            "version": component.get("version"),
            "purl": component.get("purl"),
            "component_type": component.get("type"),
            "is_root": (bom_ref == root_ref if root_ref else
                        component_index == 0 and root_component is not None),
        })
    sbom_dependencies = []
    for dependency in data.get("dependencies", []):
        parent_ref = dependency.get("ref")
        for child_ref in dependency.get("dependsOn", []):
            sbom_dependencies.append({
                "sbom_id": sbom_id,
                "source_sha256": source_sha256,
                "parent_bom_ref": parent_ref,
                "child_bom_ref": child_ref,
            })
    return {
        "sboms": pd.DataFrame(sboms),
        "sbom_components": pd.DataFrame(sbom_components),
        "sbom_dependencies": pd.DataFrame(sbom_dependencies),
    }



def matched_ids(data_dir, entry, request, demo=False):
    """Verify exact request identity and pagination chain before extracting IDs."""
    evidence = read_snapshot(data_dir, entry)
    if demo:
        return result_ids(evidence)
    if evidence.get('kind') != 'batch_evidence' or evidence.get('request') != request:
        raise ValueError('Query evidence identity mismatch')
    pages = evidence.get('pages')
    if not isinstance(pages, list) or not pages:
        raise ValueError('Missing batch evidence pages')
    ids, token = set(), None
    for i, page in enumerate(pages):
        if i and not token:
            raise ValueError('Unexpected additional OSV page')
        sent = read_snapshot(data_dir, page['request'])['queries']
        received = read_snapshot(data_dir, page['response'])['results']
        index = page['index']
        if type(index) is not int or not 0 <= index < len(sent) or len(sent) != len(received):
            raise ValueError('Batch index or cardinality mismatch')
        expected = dict(request, page_token=token) if token else request
        if sent[index] != expected:
            raise ValueError('Stored POST request does not match component')
        result = received[index]
        ids |= result_ids(result)
        token = result.get('next_page_token')
    if token:
        raise ValueError('Incomplete OSV pagination')
    return ids


def main(data_dir=None, demo=False):
    """Rebuild facts from all committed manifests and select latest query state."""
    data_dir = Path(data_dir) if data_dir is not None else ROOT/'data'/ 'demo' if demo else ROOT/'data'
    contracts = read_schema_contracts(SQL_DIR)
    bucket_name = os.getenv('BRONZE_BUCKET', '').strip()
    if bucket_name:
        from google.cloud import storage
        bucket = storage.Client().bucket(bucket_name)
        blobs = sorted(
            (b for b in bucket.list_blobs(prefix='metadata/runs/') if b.name.endswith('.json')),
            key=lambda b: b.name,
        )
        manifests = [(f'gs://{bucket_name}/{b.name}', json.loads(b.download_as_bytes())) for b in blobs]
    else:
        paths = sorted((data_dir / 'metadata' / 'runs').glob('*.json'))
        manifests = [(str(path), json.loads(path.read_text())) for path in paths]
    if not manifests:
        raise ValueError(f'No run manifests in {data_dir}')
    collected = {name: [] for name in KEYS}
    inventories, latest = {}, {}
    def collect(frames):
        for table, frame in frames.items():
            collected[table].append(frame)
    for path in paths:
        manifest = json.loads(path.read_text())
        if not isinstance(manifest, dict) or manifest.get('format_version') != 3:
            raise ValueError(f'Legacy/unsupported manifest: {path}; archive it outside runs and recapture')
        if manifest.get('mode') != ('SYNTHETIC_OFFLINE' if demo else 'LIVE'):
            raise ValueError(f'Wrong ingestion mode: {path}')
        for entry in manifest['sboms']:
            doc = read_snapshot(data_dir, entry)
            root, refs = inventory(doc)
            sha, app = entry['sha256'], entry['application_id']
            if sha in inventories and inventories[sha][0] != (app, entry.get('provenance', {}).get('release_tag')):
                raise ValueError('One identical SBOM cannot identify two applications in this schema')
            inventories[sha] = ((app, entry.get('provenance', {}).get('release_tag')), root, refs)
            frames = transform_cyclonedx(doc, sha, app, entry['retrieved_at'])
            meta = entry.get('provenance', {})
            if not demo:
                if meta.get('sbom_sha256') != sha or meta.get('application_id') != app:
                    raise ValueError('Inventory provenance mismatch')
                if any(not meta.get(k) for k in ('release_tag','repository_url','git_commit','commit_at','java_version','maven_version','generator_version','generated_at')):
                    raise ValueError('Incomplete live inventory provenance')
            for field in ('release_tag','repository_url','git_commit','commit_at','java_version','maven_version','generator_version','generated_at'):
                frames['sboms'][field] = meta.get(field)
            collect(frames)
        for entry in manifest['advisories']:
            doc = read_snapshot(data_dir, entry)
            validate_raw_schema(doc, 'osv')
            collect(transform_osv(doc, entry['sha256'], entry['retrieved_at']))
        for record in manifest['queries']:
            sha, ref = record['sbom_sha256'], record['bom_ref']
            _, root, refs = inventories[sha]
            if ref == root or ref not in refs:
                raise ValueError('Query refers to unknown or root component')
            comp = refs[ref]
            request = record['request']
            if request != maven_request(comp):
                raise ValueError('Query package/version does not match SBOM component')
            status = record['status']
            if status not in ('SUCCESS', 'FAILED', 'SKIPPED') or (status == 'SKIPPED') != (request is None):
                raise ValueError('Invalid query status or identity')
            entry = record.get('evidence')
            if status == 'SUCCESS' and not entry:
                raise ValueError('Successful query has no evidence')
            if status != 'SUCCESS' and entry:
                read_snapshot(data_dir, entry)  # verify partial evidence without promoting matches
            ids = matched_ids(data_dir, entry, request, demo) if status == 'SUCCESS' else set()
            row = {'source_sha256': sha, 'bom_ref': ref,
                   'package_name': request['package']['name'] if request else None,
                   'component_version': comp.get('version'),
                   'osv_query_sha256': entry['sha256'] if entry else None,
                   'raw_response_path': entry['path'] if entry else None,
                   'queried_at': record['queried_at'], 'status': status,
                   'ecosystem': request['package']['ecosystem'] if request else None,
                   'error': record.get('error')}
            timestamp = pd.to_datetime(row['queried_at'], utc=True, format='ISO8601').floor('us')
            key = (sha, ref)
            if key not in latest or timestamp >= latest[key][0]:
                latest[key] = (timestamp, row, ids)
    for _, row, ids in latest.values():
        collected['component_queries'].append(pd.DataFrame([row]))
        collected['component_findings'].append(pd.DataFrame([
            {'source_sha256': row['source_sha256'], 'bom_ref': row['bom_ref'],
             'vulnerability_id': osv_id, 'osv_query_sha256': row['osv_query_sha256']}
            for osv_id in sorted(ids)]))
    frames = {name: pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()
              for name, parts in collected.items()}
    frames = normalize_and_validate_dataframes(frames, contracts)
    for name, frame in frames.items():
        # First seen for immutable facts; latest query was selected explicitly.
        if 'retrieved_at' in frame.columns:
            frame = frame.sort_values('retrieved_at', kind='stable')
        frames[name] = frame.drop_duplicates(KEYS[name], keep='first').reset_index(drop=True)
    return frames


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo', action='store_true')
    args = parser.parse_args()
    for name, frame in main(demo=args.demo).items():
        print(f'{name}: {len(frame)} rows')
