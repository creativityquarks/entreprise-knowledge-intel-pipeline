"""Validate the MVP Silver contract without modifying source files or BigQuery.

The six SQL DDL files are the single source of truth for Silver fields.
Only the project's simple CREATE TABLE IF NOT EXISTS syntax is supported;
unsupported DDL fails closed. Raw checks are structural, not full official
OSV/CycloneDX JSON Schema validation. No network calls occur on import.
"""
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re

import pandas as pd
from pandas.api.types import is_bool, is_float, is_integer, is_scalar


class SchemaValidationError(ValueError):
    """Input or destination does not conform to the expected schema."""


@dataclass(frozen=True)
class Field:
    name: str
    type: str
    mode: str  # NULLABLE, REQUIRED or REPEATED


TABLES = (
    "sboms", "sbom_components", "sbom_dependencies", "vulnerabilities",
    "affected_packages", "affected_version_events",
)

DDL = re.compile(
    r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+"
    r"`\{\{PROJECT_ID\}\}\.\{\{DATASET\}\}\.(\w+)`\s*"
    r"\((.*?)\)\s*;\s*", re.IGNORECASE | re.DOTALL,
)
COLUMN = re.compile(
    r"(\w+)\s+(STRING|INT64|BOOL|TIMESTAMP|ARRAY<STRING>)(\s+NOT\s+NULL)?",
    re.IGNORECASE,
)


def read_schema_contracts(sql_dir: Path) -> dict[str, tuple[Field, ...]]:
    """Read the six approved DDL contracts; reject unknown or unsafe SQL."""
    contracts = {}
    for path in sorted(Path(sql_dir).glob("*.sql")):
        match = DDL.fullmatch(path.read_text(encoding="utf-8").strip())
        if not match:
            raise SchemaValidationError(f"Unsupported or unsafe DDL: {path}")
        table, body = match.groups()
        fields = []
        for definition in body.split(","):
            column = COLUMN.fullmatch(definition.strip())
            if not column:
                raise SchemaValidationError(f"{path}: invalid column {definition!r}")
            name, kind, required = column.groups()
            kind = kind.upper()
            if kind == "ARRAY<STRING>":
                if required:
                    raise SchemaValidationError(f"{path}: invalid array mode")
                fields.append(Field(name, "STRING", "REPEATED"))
            else:
                fields.append(Field(name, kind, "REQUIRED" if required else "NULLABLE"))
        if table in contracts or len({f.name for f in fields}) != len(fields):
            raise SchemaValidationError(f"{path}: duplicate table or column")
        contracts[table] = tuple(fields)
    if set(contracts) != set(TABLES):
        raise SchemaValidationError(f"Expected tables {TABLES}; found {tuple(contracts)}")
    return contracts


def _require(condition, message):
    if not condition:
        raise SchemaValidationError(message)


def _objects(obj, key, context):
    """Check an optional array of objects, returning an empty list if absent."""
    values = obj.get(key, [])
    _require(isinstance(values, list) and all(isinstance(v, dict) for v in values),
             f"{context}.{key}: expected array of objects")
    return values


def _strings(obj, key, context):
    values = obj.get(key, [])
    _require(isinstance(values, list) and all(isinstance(v, str) for v in values),
             f"{context}.{key}: expected array of strings")


def validate_raw_schema(data, source_type):
    """Check the raw structures consumed by the existing transformations."""
    _require(isinstance(data, dict), f"{source_type}: expected JSON object")
    if source_type == "osv":
        for key in ("id", "modified"):
            _require(isinstance(data.get(key), str) and bool(data[key].strip()),
                     f"OSV.{key}: required non-empty string")
        _strings(data, "aliases", "OSV")
        for affected in _objects(data, "affected", "OSV"):
            _require(isinstance(affected.get("package", {}), dict),
                     "OSV.affected.package: expected object")
            _strings(affected, "versions", "OSV.affected")
            for version_range in _objects(affected, "ranges", "OSV.affected"):
                for event in _objects(version_range, "events", "OSV.range"):
                    _require(len(event) == 1 and all(isinstance(v, str) for v in event.values()),
                             "OSV.range.events: expected single string-valued event")
    elif source_type == "cyclonedx":
        _require(data.get("bomFormat") == "CycloneDX", "Invalid CycloneDX bomFormat")
        _require(isinstance(data.get("specVersion"), str), "CycloneDX.specVersion: expected string")
        _require(type(data.get("version")) is int and data["version"] >= 1,
                 "CycloneDX.version: expected positive integer")
        metadata = data.get("metadata", {})
        _require(isinstance(metadata, dict), "CycloneDX.metadata: expected object")
        components = _objects(data, "components", "CycloneDX")
        if "component" in metadata:
            _require(isinstance(metadata["component"], dict), "CycloneDX.metadata.component: expected object")
            components = [metadata["component"], *components]
        for component in components:
            _require(isinstance(component.get("name"), str) and bool(component["name"].strip()),
                     "CycloneDX.component.name: required non-empty string")
        for dependency in _objects(data, "dependencies", "CycloneDX"):
            _require(isinstance(dependency.get("ref"), str), "CycloneDX.dependency.ref: required string")
            _strings(dependency, "dependsOn", "CycloneDX.dependency")
    else:
        raise SchemaValidationError(f"Unsupported source type: {source_type}")


def _missing(value):
    return is_scalar(value) and bool(pd.isna(value))


def normalize_and_validate_dataframes(dataframes, contracts):
    """Return copies with validated columns, nullability, arrays and scalar types.

    UTC timestamps are floored to microseconds for BigQuery. Nullable integers
    use pandas Int64. Integral floats from pandas null inference are accepted
    only within the exactly representable integer range. No invalid values are
    silently coerced to null. Missing tables are valid for incremental runs.
    """
    result = {}
    for table, original in dataframes.items():
        _require(table in contracts, f"Unexpected Silver table: {table}")
        _require(isinstance(original, pd.DataFrame), f"{table}: expected DataFrame")
        fields = contracts[table]
        names = [f.name for f in fields]
        # Existing transforms produce a zero-column frame for an empty row list.
        if original.shape == (0, 0):
            original = pd.DataFrame(columns=names)
        _require(original.columns.is_unique and set(original.columns) == set(names),
                 f"{table}: expected columns {names}; got {list(original.columns)}")
        df = original.loc[:, names].copy()
        for field in fields:
            col = df[field.name]
            context = f"{table}.{field.name}"
            for row, value in enumerate(col):
                if field.mode == "REPEATED":
                    valid = isinstance(value, list) and all(isinstance(v, str) for v in value)
                elif _missing(value):
                    valid = field.mode != "REQUIRED"
                elif field.type == "STRING":
                    valid = isinstance(value, str)
                elif field.type == "INT64":
                    valid = (is_integer(value) and not is_bool(value)) or (
                        is_float(value) and abs(value) <= 2**53 - 1 and float(value).is_integer()
                    )
                    valid = valid and -(2**63) <= int(value) < 2**63
                elif field.type == "BOOL":
                    valid = is_bool(value)
                elif field.type == "TIMESTAMP":
                    valid = isinstance(value, (str, datetime))
                else:
                    valid = False
                _require(valid, f"{context}: invalid value at row {row}; expected {field.type}/{field.mode}")
            try:
                if field.mode == "REPEATED":
                    continue
                if field.type == "TIMESTAMP":
                    df[field.name] = pd.to_datetime(col, utc=True, format="ISO8601", errors="raise").dt.floor("us")
                elif field.type == "INT64":
                    df[field.name] = col.astype("Int64")
                elif field.type == "BOOL":
                    df[field.name] = col.astype("boolean")
                elif field.type == "STRING":
                    df[field.name] = col.astype("string")
            except (ValueError, TypeError, OverflowError) as exc:
                raise SchemaValidationError(f"{context}: normalization failed: {exc}") from exc
            if field.mode == "REQUIRED":
                _require(not df[field.name].isna().any(), f"{context}: required value is null")
        result[table] = df
    return result


def validate_bigquery_schemas(client, project_id, dataset, contracts):
    """Compare actual BigQuery field names, types and modes with the DDL.

    Read-only metadata operation. Column order is immaterial. A mismatch raises
    before uploads; no automatic migration, deletion or schema mutation occurs.
    """
    aliases = {"INTEGER": "INT64", "BOOLEAN": "BOOL"}
    for table, fields in contracts.items():
        table_id = f"{project_id}.{dataset}.{table}"
        actual = client.get_table(table_id)
        expected = {f.name: (f.type, f.mode) for f in fields}
        observed = {f.name: (aliases.get(f.field_type.upper(), f.field_type.upper()),
                             (f.mode or "NULLABLE").upper()) for f in actual.schema}
        differences = [f"{name}: expected {expected.get(name)}, actual {observed.get(name)}"
                       for name in sorted(expected.keys() | observed.keys())
                       if expected.get(name) != observed.get(name)]
        if differences:
            raise SchemaValidationError(f"{table_id}: schema mismatch; " + "; ".join(differences))
