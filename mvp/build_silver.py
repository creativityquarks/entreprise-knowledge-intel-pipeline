"""Normalize local Bronze snapshots into validated Silver DataFrames.
Return a pending checkpoint; only the persistence layer commits it.
"""
import json
from pathlib import Path

import pandas as pd
from schema_validation import (
    read_schema_contracts, validate_raw_schema,
    normalize_and_validate_dataframes,
)

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
SQL_DIR = ROOT / "sql"
MANIFEST_DIR = DATA / "metadata" / "runs"
RAW_DIR = DATA / "raw"
STATE_FILE = DATA / "metadata" / "silver_state.json"
TRANSFORM_VERSION = 9


def read_json(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def load_state():
    if STATE_FILE.exists():
        state = read_json(STATE_FILE)
        if state.get("transform_version") == TRANSFORM_VERSION:
            return state
    return {"transform_version": TRANSFORM_VERSION, "processed": []}


def save_state(state):
    """Atomically replace the local checkpoint after successful persistence."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = STATE_FILE.with_suffix(".tmp")
    with open(temporary_file, "w", encoding="utf-8") as file:
        json.dump(state, file, indent=2)
    temporary_file.replace(STATE_FILE)


def get_manifest_records(path):
    manifest = read_json(path)
    if isinstance(manifest, list):
        return manifest
    for key in ("records", "sources", "results"):
        if isinstance(manifest.get(key), list):
            return manifest[key]
    raise ValueError(f"Unsupported manifest structure: {path}")


def get_source_type(record):
    source_type = record.get("source_type")
    if source_type:
        return source_type.lower()
    name = record.get("name", "").lower()
    if name.startswith("osv_"):
        return "osv"
    if name.startswith("cyclonedx_"):
        return "cyclonedx"
    return None


def get_raw_path(record):
    file_path = record.get("file_path")
    if file_path:
        path = Path(file_path)
        if path.is_absolute() and path.exists():
            return path
        for candidate in (DATA / path, ROOT / path):
            if candidate.exists():
                return candidate
    return RAW_DIR / record["name"] / f"{record['sha256']}.json"


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


def transform_cyclonedx(data, source_sha256):
    """Flatten SBOM inventory and dependsOn edges; retain root identity."""
    metadata = data.get("metadata", {})
    root_component = metadata.get("component")
    components = list(data.get("components", []))
    root_ref = None
    if root_component:
        root_ref = root_component.get("bom-ref")
        existing_refs = {component.get("bom-ref") for component in components}
        if root_ref not in existing_refs:
            components.insert(0, root_component)
    sbom_id = data.get("serialNumber") or source_sha256
    sboms = [{
        "sbom_id": sbom_id,
        "serial_number": data.get("serialNumber"),
        "spec_version": data.get("specVersion"),
        "version": data.get("version"),
        "metadata_timestamp": metadata.get("timestamp"),
        "root_component_ref": root_ref,
        "source_sha256": source_sha256,
        "retrieved_at": None,
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


def process_source(record, state):
    """Validate one supported raw snapshot and stage its checkpoint in memory."""
    source_type = get_source_type(record)
    if source_type not in ("osv", "cyclonedx"):
        return None
    source_sha256 = record.get("sha256")
    if not source_sha256:
        return None
    source_key = f"{source_type}:{source_sha256}"
    if source_key in state["processed"]:
        print(f"Already processed: {source_key}")
        return None
    status_code = record.get("status_code")
    if status_code is not None and not 200 <= int(status_code) < 300:
        print(f"Skipping unsuccessful source: {source_key}")
        return None
    raw_path = get_raw_path(record)
    if not raw_path.exists():
        print(f"Raw file not found: {raw_path}")
        return None
    data = read_json(raw_path)
    validate_raw_schema(data, source_type)
    retrieved_at = record.get("retrieved_utc") or record.get("retrieved_at")
    if source_type == "osv":
        dfs = transform_osv(data, source_sha256, retrieved_at)
    else:
        dfs = transform_cyclonedx(data, source_sha256)
        if not dfs["sboms"].empty:
            dfs["sboms"].loc[0, "retrieved_at"] = retrieved_at
    state["processed"].append(source_key)
    print(f"Processed: {source_key}")
    return dfs


def main():
    """Return validated DataFrames and an uncommitted source checkpoint."""
    contracts = read_schema_contracts(SQL_DIR)
    state = load_state()
    manifest_files = sorted(MANIFEST_DIR.glob("*.json"))
    if not manifest_files:
        print("No manifests found.")
        return {}, state
    collected = {}
    for manifest_path in manifest_files:
        for record in get_manifest_records(manifest_path):
            dfs = process_source(record, state)
            if not dfs:
                continue
            for table_name, df in dfs.items():
                collected.setdefault(table_name, []).append(df)
    result = {
        table_name: pd.concat(frames, ignore_index=True)
        for table_name, frames in collected.items() if frames
    }
    result = normalize_and_validate_dataframes(result, contracts)
    print("\nSilver transformation and validation completed.")
    return result, state


if __name__ == "__main__":
    # Dry run: never commit a checkpoint from this entry point.
    silver_dfs, _ = main()
    for table_name, df in silver_dfs.items():
        print(f"{table_name}: {len(df)} rows")
