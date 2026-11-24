import os
import json
import hashlib
from pathlib import Path

from dotenv import load_dotenv
from google.cloud import bigquery
from google.api_core.exceptions import Conflict
import pandas as pd


# --------------------------------------------------
# Configuration
# --------------------------------------------------

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
    "vulnerabilities",
    "affected_packages",
    "affected_version_events",
    "sboms",
    "sbom_components",
    "sbom_dependencies",
]


# --------------------------------------------------
# Checkpoint
# --------------------------------------------------

def load_state():
    if not STATE_FILE.exists():
        return {"loaded": []}

    with open(STATE_FILE, encoding="utf-8") as file:
        return json.load(file)


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    temporary_file = STATE_FILE.with_suffix(".tmp")

    with open(temporary_file, "w", encoding="utf-8") as file:
        json.dump(state, file, indent=2)

    temporary_file.replace(STATE_FILE)


# --------------------------------------------------
# Create BigQuery tables from SQL
# --------------------------------------------------

def create_dataset(client):
    dataset_id = f"{PROJECT_ID}.{DATASET}"

    dataset = bigquery.Dataset(dataset_id)
    dataset.location = LOCATION

    dataset = client.create_dataset(
        dataset,
        exists_ok=True,
    )

    print(f"Dataset ready: {dataset.full_dataset_id}")


def create_tables(client):
    sql_files = sorted(SQL_DIR.glob("*.sql"))

    if not sql_files:
        raise FileNotFoundError(f"No SQL files found in {SQL_DIR}")

    for sql_file in sql_files:
        query = sql_file.read_text(encoding="utf-8")

        query = query.replace("{{PROJECT_ID}}", PROJECT_ID)
        query = query.replace("{{DATASET}}", DATASET)

        print(f"Executing {sql_file.name}...")

        job = client.query(query, location=LOCATION)
        job.result()

        print(f"Created/verified table from {sql_file.name}")


# --------------------------------------------------
# DataFrame hash
# --------------------------------------------------

def get_dataframe_hash(df: pd.DataFrame) -> str:
    payload = df.to_json(orient="records", date_format="iso").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# --------------------------------------------------
# Load DataFrame into BigQuery
# --------------------------------------------------

def load_dataframe(client, table_name: str, df: pd.DataFrame, df_hash: str):
    table_id = f"{PROJECT_ID}.{DATASET}.{table_name}"
    job_id = f"silver_{table_name}_{df_hash}"

    job_config = bigquery.LoadJobConfig(
        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
    )

    try:
        print("Project:", client.project)
        print("Destination:", table_id)
        job = client.load_table_from_dataframe(
            df,
            table_id,
            job_id=job_id,
            job_config=job_config,
            location=LOCATION,
        )
    except Conflict:
        job = client.get_job(job_id, location=LOCATION)

    job.result()

    print(f"Loaded {len(df)} rows -> {table_id}")


# --------------------------------------------------
# Main
# --------------------------------------------------

def main(dataframes: dict[str, pd.DataFrame] | None = None):
    silver_state = None
    if dataframes is None:
        # Adjust this import to match your Silver module filename (without .py).
            from build_silver import main as run_silver, save_state as save_silver_state
            dataframes, silver_state = run_silver()

    client = bigquery.Client(project=PROJECT_ID)

    create_dataset(client)
    create_tables(client)
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

        load_dataframe(
            client,
            table_name,
            df,
            df_hash,
        )

        state["loaded"].append(load_key)
        save_state(state)

    if silver_state is not None:
        save_silver_state(silver_state)

    print("\nBigQuery ingestion completed.")


if __name__ == "__main__":
    main()
