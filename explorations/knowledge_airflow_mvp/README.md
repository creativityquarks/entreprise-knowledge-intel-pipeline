# Enterprise Knowledge Intelligence Pipeline — Airflow-first MVP

The complete, shortened tutorial is in:

- [`docs/01_AIRFLOW_FIRST_KNOWLEDGE_MVP.md`](docs/01_AIRFLOW_FIRST_KNOWLEDGE_MVP.md)
- [`docs/01_AIRFLOW_FIRST_KNOWLEDGE_MVP.pdf`](docs/01_AIRFLOW_FIRST_KNOWLEDGE_MVP.pdf)

## What is included?

A daily Airflow 2.10 DAG on Docker Compose, using Poetry to execute Python GCS ingestion, BigQuery Silver upserts and dbt Gold models. A Streamlit dashboard shows application findings. The two CycloneDX inventories are **synthetic**; OSV responses are retrieved from the **live** public API.

## Quick start on GCE VM

1. Configure GCS bucket and EU BigQuery datasets + attached VM service account as described in the tutorial.
2. `cp .env.example .env`; edit `GCP_PROJECT`, `BRONZE_BUCKET`, `AIRFLOW_ADMIN_PASSWORD`, `AIRFLOW_SECRET_KEY`.
3. `sed "s/PROJECT_ID/${GCP_PROJECT}/g" sql/setup.sql | bq query --location=EU --use_legacy_sql=false` (export `GCP_PROJECT` in shell first).
4. `mkdir -p logs && sudo chown -R 50000:0 logs`
5. `docker compose build`
6. `docker compose up airflow-init`
7. `docker compose up -d airflow-webserver airflow-scheduler dashboard`
8. Airflow: `http://localhost:8080`; enable and manually trigger `knowledge_mvp`.
9. Streamlit: `http://localhost:8501`. Both ports bind only to VM loopback, so use SSH port forwarding from your Mac.

Unit tests: `docker compose exec airflow-scheduler poetry run pytest -q`.

**Security:** `.env` is ignored by Git; use a dedicated VM service account, least-privilege IAM and no service-account keyfile.

**Execution status:** Python unit tests were executed locally (4 passed), source files were syntax-checked, YAML parsed, and the PDF navigation was verified. Docker builds, live OSV calls and GCP operations require the team's environment and **have not been executed here**.
