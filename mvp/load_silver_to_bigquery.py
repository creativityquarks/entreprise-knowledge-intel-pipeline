"""Persist validated Silver DataFrames to BigQuery and commit checkpoints.
Schema migration is deliberately outside this normal ingestion path.
"""
import os
import json
import hashlib
from pathlib import Path

from dotenv import load_dotenv
from google.cloud import bigquery
from google.api_core.exceptions import Conflict
import pandas as pd

from build_silver import main as run_silver, save_state as save_silver_state
from schema_validation import (
    read_schema_contracts, normalize_and_validate_dataframes,
    validate_bigquery_schemas,
)

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
PROJECT_ID = os.getenv("GCP_PROJECT_ID")
DATASET = os.getenv("BQ_DATASET")
LOCATION = os.getenv("BQ_LOCATION", "EU")
if not PROJECT_ID or not DATASET:
    raise ValueError("GCP_PROJECT_ID and BQ_DATASET must be defined in .env")
SQL_DIR = ROOT / "sql"
STATE_FILE = ROOT / "data" / "metadata" / "bigquery_state.json"
TABLES = [
    "vulnerabilities", "affected_packages", "affected_version_events",
    "sboms", "sbom_components", "sbom_dependencies",
]


def load_state():
    if not STATE_FILE.exists():
        return {"loaded": []}
    with open(STATE_FILE, encoding="utf-8") as file:
        return json.load(file)


def save_state(state):
    """Record completed uploads using an atomic local file replacement."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = STATE_FILE.with_suffix(".tmp")
    with open(temporary_file, "w", encoding="utf-8") as file:
        json.dump(state, file, indent=2)
    temporary_file.replace(STATE_FILE)


def create_dataset(client):
    dataset_id = f"{PROJECT_ID}.{DATASET}"
    dataset = bigquery.Dataset(dataset_id)
    dataset.location = LOCATION
    dataset = client.create_dataset(dataset, exists_ok=True)
    print(f"Dataset ready: {dataset.full_dataset_id}")


def create_tables(client):
    """Execute the previously validated, non-destructive SQL DDL files."""
    sql_files = sorted(SQL_DIR.glob("*.sql"))
    if not sql_files:
        raise FileNotFoundError(f"No SQL files found in {SQL_DIR}")
    for sql_file in sql_files:
        query = sql_file.read_text(encoding="utf-8")
        query = query.replace("{{PROJECT_ID}}", PROJECT_ID)
        query = query.replace("{{DATASET}}", DATASET)
        print(f"Executing {sql_file.name}...")
        client.query(query, location=LOCATION).result()
        print(f"Created/verified table from {sql_file.name}")


def get_dataframe_hash(df: pd.DataFrame) -> str:
    """Hash normalized records, retaining microsecond timestamp precision."""
    payload = df.to_json(orient="records", date_format="iso", date_unit="us").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_dataframe(client, table_name: str, df: pd.DataFrame, df_hash: str):
    """Append a validated batch; recover a previously submitted identical job."""
    table_id = f"{PROJECT_ID}.{DATASET}.{table_name}"
    job_id = f"silver_{table_name}_{df_hash}"
    job_config = bigquery.LoadJobConfig(
        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
        create_disposition=bigquery.CreateDisposition.CREATE_NEVER,
        schema=client.get_table(table_id).schema,
    )
    try:
        print("Project:", client.project)
        print("Destination:", table_id)
        job = client.load_table_from_dataframe(
            df, table_id, job_id=job_id, job_config=job_config, location=LOCATION,
        )
    except Conflict:
        job = client.get_job(job_id, location=LOCATION)
    job.result()
    print(f"Loaded/confirmed {len(df)} rows -> {table_id}")


def main(dataframes: dict[str, pd.DataFrame] | None = None):
    """Validate contracts and destination before writing any rows."""
    contracts = read_schema_contracts(SQL_DIR)
    silver_state = None
    if dataframes is None:
        dataframes, silver_state = run_silver()
    else:
        dataframes = normalize_and_validate_dataframes(dataframes, contracts)
    client = bigquery.Client(project=PROJECT_ID)
    create_dataset(client)
    create_tables(client)
    validate_bigquery_schemas(client, PROJECT_ID, DATASET, contracts)
    print("BigQuery schemas validated.")
    state = load_state()
    for table_name in TABLES:
        df = dataframes.get(table_name)
        if df is None or df.empty:
            continue
        df_hash = get_dataframe_hash(df)
        load_key = f"{table_name}/{df_hash}"
        if load_key in state["loaded"]:
            print(f"Already loaded: {table_name} ({df_hash[:12]})")
            continue
        print(f"Uploading: {table_name} ({len(df)} rows)")
        load_dataframe(client, table_name, df, df_hash)
        state["loaded"].append(load_key)
        save_state(state)
    if silver_state is not None:
        save_silver_state(silver_state)
    print("\nBigQuery ingestion completed.")


if __name__ == "__main__":
    main()
