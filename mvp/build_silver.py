# /!\ Don't execute this scripts separately: load_silver_to_bigquery.py already calls this one.

import json
from pathlib import Path

import pandas as pd


# --------------------------------------------------
# Paths and configuration
# --------------------------------------------------

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"

MANIFEST_DIR = DATA / "metadata" / "runs"
RAW_DIR = DATA / "raw"
STATE_FILE = DATA / "metadata" / "silver_state.json"

TRANSFORM_VERSION = 9


# --------------------------------------------------
# Read and save JSON / checkpoint
# --------------------------------------------------

def read_json(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def load_state():
    if not STATE_FILE.exists():
        return {
            "transform_version": TRANSFORM_VERSION,
            "processed": []
        }

    state = read_json(STATE_FILE)

    # Reprocess everything if transformation logic changed.
    if state.get("transform_version") != TRANSFORM_VERSION:
        return {
            "transform_version": TRANSFORM_VERSION,
            "processed": []
        }

    return state


def save_state(state):
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

    return []


# --------------------------------------------------
# Identify source and locate raw JSON
# --------------------------------------------------

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

    # Fallback for manifests without file_path.
    return RAW_DIR / record["name"] / f"{record['sha256']}.json"


# --------------------------------------------------
# OSV transformation
# --------------------------------------------------

def transform_osv(data, source_sha256, retrieved_at):
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

        for range_index, version_range in enumerate(
            affected.get("ranges", [])
        ):
            for event_index, event in enumerate(
                version_range.get("events", [])
            ):
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


# --------------------------------------------------
# CycloneDX transformation
# --------------------------------------------------

def transform_cyclonedx(data, source_sha256):
    metadata = data.get("metadata", {})
    root_component = metadata.get("component")

    components = list(data.get("components", []))

    root_ref = None

    if root_component:
        root_ref = root_component.get("bom-ref")

        # Add the root component if it is not already in components.
        existing_refs = {
            component.get("bom-ref")
            for component in components
        }

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
        "retrieved_at": None,  # Filled by the caller.
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
            "is_root": (
                bom_ref == root_ref
                if root_ref
                else component_index == 0 and root_component is not None
            ),
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


# --------------------------------------------------
# Process one source
# --------------------------------------------------

def process_source(record, state):
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

    # Ignore unsuccessful HTTP responses when a status code is available.
    status_code = record.get("status_code")

    if status_code is not None and not 200 <= int(status_code) < 300:
        print(f"Skipping unsuccessful source: {source_key}")
        return None

    raw_path = get_raw_path(record)

    if not raw_path.exists():
        print(f"Raw file not found: {raw_path}")
        return None

    data = read_json(raw_path)

    retrieved_at = (
        record.get("retrieved_utc")
        or record.get("retrieved_at")
    )

    if source_type == "osv":
        dfs = transform_osv(data, source_sha256, retrieved_at)
    else:
        dfs = transform_cyclonedx(data, source_sha256)
        if not dfs["sboms"].empty:
            dfs["sboms"].loc[0, "retrieved_at"] = retrieved_at

    state["processed"].append(source_key)

    print(f"Processed: {source_key}")
    return dfs


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():
    state = load_state()

    manifest_files = sorted(MANIFEST_DIR.glob("*.json"))

    if not manifest_files:
        print("No manifests found.")
        return {}, state

    collected = {}

    for manifest_path in manifest_files:
        records = get_manifest_records(manifest_path)

        for record in records:
            dfs = process_source(record, state)
            if not dfs:
                continue

            for table_name, df in dfs.items():
                collected.setdefault(table_name, []).append(df)

    result = {
        table_name: pd.concat(frames, ignore_index=True)
        for table_name, frames in collected.items()
        if frames
    }

    print("\nSilver transformation completed.")
    return result, state


if __name__ == "__main__":
    silver_dfs = main()
