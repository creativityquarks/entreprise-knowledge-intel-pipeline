from datetime import datetime, timedelta, timezone
from pathlib import Path

from airflow import DAG
from airflow.operators.bash import BashOperator

MVP_DIR = Path(__file__).resolve().parents[2]
PYTHON = MVP_DIR / ".venv/bin/python"


def create_pipeline(mode):

    with DAG(
        dag_id=f"knowledge_pipeline_{mode}",
        start_date=datetime(2026, 11, 26, tzinfo=timezone.utc),
        schedule=None,
        catchup=False,
        max_active_runs=1,
        default_args={
            "retries": 1,
            "retry_delay": timedelta(minutes=1),
        },
        tags=["knowledge", mode],
    ) as dag:

        def task(task_id, command, allow_partial=False):

            bash_command = f"{PYTHON} {command}"

# Orchestration exit-code contract:
# 0  = SUCCESS: continue downstream execution.
# 10 = PARTIAL: warn and continue only for authorized tasks.
# Any other nonzero code = FAILURE: retry, then block downstream.
# Airflow execution success does not imply complete data coverage.
            if allow_partial:
                bash_command += """
rc=$?

if [ "$rc" -eq 10 ]; then
    echo "WARNING: PARTIAL data coverage"
    exit 0
fi

exit "$rc"
"""

            return BashOperator(
                task_id=task_id,
                bash_command=bash_command,
                cwd=str(MVP_DIR),
                skip_on_exit_code=None,
            )

        demo_flag = " --demo" if mode == "demo" else ""

        ingestion = task(
            "ingestion",
            f"fetch_live.py --{mode}",
            allow_partial=True,
        )

        silver = task(
            "load_to_silver",
            f"load_silver_to_bigquery.py{demo_flag}",
        )

        gold = task(
            "build_gold",
            f"build_gold.py{demo_flag}",
        )

        ingestion >> silver >> gold

        if mode == "generated":
            generation = task(
                "generate_sboms",
                "generate_sboms.py",
                allow_partial=True,
            )

            generation >> ingestion

    return dag


demo_dag = create_pipeline("demo")
generated_dag = create_pipeline("generated")
