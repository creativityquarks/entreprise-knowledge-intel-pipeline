"""Daily OSV + CycloneDX fixture MVP (Airflow 2.10.x)."""
from datetime import datetime, timedelta, timezone
from airflow import DAG
from airflow.operators.bash import BashOperator

DEFAULTS = {'owner':'knowledge-team','retries':2,
            'retry_delay':timedelta(minutes=3)}

with DAG(
    dag_id='knowledge_mvp',
    description='Immutable GCS Bronze to BigQuery Silver and dbt Gold',
    default_args=DEFAULTS,
    start_date=datetime(2026, 11, 1, tzinfo=timezone.utc),
    schedule_interval='@daily',
    catchup=False,
    max_active_runs=1,
    tags=['bootcamp','osv','sbom'],
) as dag:
    fetch = BashOperator(
        task_id='fetch_and_store_bronze',
        bash_command="poetry run python src/ingest.py --run-id '{{ run_id }}'",
        cwd='/opt/pipeline',
    )
    normalize = BashOperator(
        task_id='qa_and_load_silver',
        bash_command="poetry run python src/normalize.py --run-id '{{ run_id }}'",
        cwd='/opt/pipeline',
    )
    dbt_build = BashOperator(
        task_id='dbt_build_gold',
        bash_command='poetry run dbt build --project-dir dbt --profiles-dir dbt_profiles',
        cwd='/opt/pipeline',
    )
    fetch >> normalize >> dbt_build
