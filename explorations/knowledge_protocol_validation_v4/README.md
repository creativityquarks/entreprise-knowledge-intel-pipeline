# Knowledge Pipeline — executable team exploration tutorial

**Read [`docs/VALIDATION_PROTOCOL.md`](docs/VALIDATION_PROTOCOL.md) in order (or its formatted [`PDF`](docs/VALIDATION_PROTOCOL.pdf)).** This archive is a teaching companion, not a production vulnerability assessor. It follows a deliberate learning progression: **SQLite for small curated fixtures (Section 1)**, then **PostgreSQL for real downloaded source data (Sections 2–3)**, then the production architecture plan (Section 4).

## Tutorial navigation and checkpoint answers

The Markdown and PDF contain linked tables of contents, return-to-top links at the end of subsections, syntax-highlighted examples in the PDF, and an end section titled **Checkpoints Answers**. Use answers only after attempting exercises; live-source values require independent observation.

## Section 1 — fixture knowledge graph in SQLite (no Docker needed)

On your Google VM (Ubuntu/Debian, Python 3.12 and Poetry installed):

```bash
sudo apt-get update && sudo apt-get install -y unzip sqlite3
# From your extracted knowledge_protocol_validation_team_code/ directory:
poetry env use python3.12
poetry install
poetry run python src/validate.py
poetry run python -m unittest discover -s tests -v
sqlite3 -header -column data/outputs/validation.sqlite < sql/validation_queries.sql
poetry run python -m json.tool data/outputs/graph_edges_run1.json
```

The built-in Python `sqlite3` module needs no separate package. The `sqlite3` apt package installs the **interactive CLI**. On macOS, check `sqlite3 --version`; use `brew install sqlite` if you want a newer CLI. `poetry` controls Python dependencies in both sections.

## Section 2 — real JSON → PostgreSQL

Start the isolated PostgreSQL 14 Docker container **only now** (host port 5433, internal 5432):

```bash
export DATABASE_URL='postgresql://knowledge:tutorial_local_only@127.0.0.1:5433/knowledge_lab'
docker compose -f docker-compose.tutorial.yml up -d
docker compose -f docker-compose.tutorial.yml exec -T postgres \
  pg_isready -U knowledge -d knowledge_lab
docker compose -f docker-compose.tutorial.yml exec -T postgres \
  psql -v ON_ERROR_STOP=1 -U knowledge -d knowledge_lab < sql/pg_live.sql
poetry run python src/fetch_live.py
poetry run python src/load_live_pg.py
docker compose -f docker-compose.tutorial.yml exec -T postgres \
  psql -U knowledge -d knowledge_lab < sql/pg_live_queries.sql
```

The downloads use public HTTPS. A previous Mac installation of python.org Python 3.14 lacked a trusted CA bundle and was fixed through `Install Certificates.command`. Do **not** disable certificate checks. This tutorial targets Python 3.12 and never requires the Mac's globally installed Python 3.14.

## Section 3 — validation and graph-ready JSON

```bash
poetry run pytest -q
poetry run python src/export_pg_graph.py
poetry run python -m json.tool data/outputs/pg_graph_edges_live.json
```

The PostgreSQL exporter emits **observed CycloneDX dependency edges only**, not unsupported CVE-to-package vulnerability claims. For the controlled version-matching demonstration, inspect the SQLite run 1/2 exports.

## Code map

| Section | Main files | Learning objective |
|---|---|---|
| 1A–1B | `data/fixtures/*.json`, `src/validate.py`, `sql/schema.sql`, `sql/validation_queries.sql` | Relational entities, transitive dependency paths, bounded exposure, graph export |
| 1B and 3 | `tests/test_validation.py`, `tests/test_data_contract.py` | Reproducibility, source relationships, integrity tests |
| 2A | `src/fetch_live.py`, `data/raw/live_manifest.json` (generated) | Source choice, acquisition, metadata manifest, source hashing |
| 2B | `sql/pg_live.sql`, `src/load_live_pg.py`, `sql/pg_live_queries.sql` | Real JSONB storage, normalization and joins |
| 3 | `src/export_pg_graph.py` | Graph-ready node/edge files, evidence and no false exposure claims |

The original PostgreSQL fixture lab files (`src/pg_fixture_lab.py`, `sql/pg_lab.sql`, `sql/pg_traversal.sql`) are retained under `extras/optional_pg_fixture_lab/` as **optional comparisons**, not required by any section or command of this tutorial.

## Current evidence and limits

- Previously executed SQLite baseline: five fixture snapshots, affected Billing 2.14.1 → not affected 2.17.1 under a **reduced teaching interval**, four graph nodes for each run, three → two edges, and passing unit tests. These are synthetic/curated source results.
- Earlier live Mac run: five successful HTTP 200 downloads and ~1.96 MiB total response bytes, documented in `live_manifest.json`. Actual response data is fetched independently by each teammate; no claimed live HTTP calls originate from this archive.
- The public CycloneDX CBOM is for dependency structure; it need not match Maven Log4j. A zero-result join is valid.
- PostgreSQL exercises use a disposable schema with `TRUNCATE` for replay. This **is not** incremental idempotency or immutable Bronze history.
- A full Maven version matcher, production change history, VPS API, and Neo4j integration remain future milestones.

Do not commit secrets or production database credentials. Docker Compose passwords here are local tutorial-only credentials.
