<a id="top"></a>

<a id="enterprise-knowledge-intelligence-pipeline-team-exploration-validation-tutorial"></a>

# Enterprise Knowledge Intelligence Pipeline — Team Exploration & Validation Tutorial

**Team tutorial v4 · 23 November 2026 · SQLite first, PostgreSQL second · Markdown + PDF**  
**Audience:** Le Wagon Data Engineering team, working on Google Compute Engine VMs (macOS alternatives included).  
**Goal:** understand, reproduce and validate the complete *data-to-knowledge* mechanism before building the distributed production pipeline.  
**Prerequisite:** companion ZIP package (the code and this tutorial are together under one project root) (fixtures, runnable SQLite baseline, PostgreSQL live-data exercises and tests).  
**Scope:** package/vulnerability intelligence and SBOM dependencies, up to **graph-ready node/edge files**. Actual VPS ingestion / Neo4j operation is a later integration task.

> **How to work:** Run each exercise, predict what it will do before running it, read the SQL output, and fill in the small evidence table beside the exercise. A zero-row result is data, not necessarily an error. Do not confuse our **curated** examples with genuine downloads or a bounded matching demonstration with comprehensive security assurance.

## Table of contents

Use the linked headings to jump to a section. Every subsection ends with a **Back to top** link.

- [Enterprise Knowledge Intelligence Pipeline — Team Exploration & Validation Tutorial](#enterprise-knowledge-intelligence-pipeline-team-exploration-validation-tutorial)
  - [Learning map and four acceptance gates](#learning-map-and-four-acceptance-gates)
- [Section 1 — Understand the mechanism using tiny fixtures](#section-1-understand-the-mechanism-using-tiny-fixtures)
  - [Part A — Follow the entities and relationships, without infrastructure distractions](#part-a-follow-the-entities-and-relationships-without-infrastructure-distractions)
    - [1A.1. Read a Software Bill of Materials (SBOM)](#1a-1-read-a-software-bill-of-materials-sbom)
    - [1A.2. Read an OSV advisory — a different perspective](#1a-2-read-an-osv-advisory-a-different-perspective)
    - [1A.3. Join two perspectives and create knowledge](#1a-3-join-two-perspectives-and-create-knowledge)
    - [1A.4. Model the other two source types](#1a-4-model-the-other-two-source-types)
    - [1A.5. Simulate change: remediation and history](#1a-5-simulate-change-remediation-and-history)
    - [1A.6. From rows to graph-ready entities](#1a-6-from-rows-to-graph-ready-entities)
    - [Checkpoint 1A — Write three sentences before running code](#checkpoint-1a-write-three-sentences-before-running-code)
  - [Part B — Execute the fixture demonstration with SQLite (no server)](#part-b-execute-the-fixture-demonstration-with-sqlite-no-server)
    - [1B.1. Set up the Google VM and Poetry](#1b-1-set-up-the-google-vm-and-poetry)
    - [1B.2. Run the *existing* curated fixture pipeline](#1b-2-run-the-existing-curated-fixture-pipeline)
    - [1B.3. Explore the database using the SQLite CLI](#1b-3-explore-the-database-using-the-sqlite-cli)
    - [1B.4. Use SQL to reveal direct and transitive relationships](#1b-4-use-sql-to-reveal-direct-and-transitive-relationships)
    - [1B.5. Inspect the graph-ready knowledge without a graph server](#1b-5-inspect-the-graph-ready-knowledge-without-a-graph-server)
    - [1B.6. Validate and interpret what *idempotency* means here](#1b-6-validate-and-interpret-what-idempotency-means-here)
- [Section 2 — Retrieve real source data and build a second, honest proof](#section-2-retrieve-real-source-data-and-build-a-second-honest-proof)
  - [Part A — Choose a coherent dataset before downloading anything](#part-a-choose-a-coherent-dataset-before-downloading-anything)
  - [2.0. Switch to PostgreSQL for the real-data laboratory](#2-0-switch-to-postgresql-for-the-real-data-laboratory)
    - [2A.1. A minimal *proof-of-concept question* determines the sources](#2a-1-a-minimal-proof-of-concept-question-determines-the-sources)
    - [2A.2. Run the previously tested downloader](#2a-2-run-the-previously-tested-downloader)
    - [2A.3. Understand the **manifest**, not just the JSON](#2a-3-understand-the-manifest-not-just-the-json)
    - [2A.4. Explore the five JSON files — learn the schemas with tiny commands](#2a-4-explore-the-five-json-files-learn-the-schemas-with-tiny-commands)
  - [Part B — Normalize real data into PostgreSQL, query the relationships, test claims](#part-b-normalize-real-data-into-postgresql-query-the-relationships-test-claims)
    - [2B.1. First make the target relational model explicit](#2b-1-first-make-the-target-relational-model-explicit)
    - [2B.2. Extend PostgreSQL with a live-source schema](#2b-2-extend-postgresql-with-a-live-source-schema)
    - [2B.3. Write the live loader (read local raw JSON, never refetch inside transformations)](#2b-3-write-the-live-loader-read-local-raw-json-never-refetch-inside-transformations)
    - [2B.4. Query source identities and dependencies](#2b-4-query-source-identities-and-dependencies)
    - [2B.5. Try a real package join — understand the meaning of zero matches](#2b-5-try-a-real-package-join-understand-the-meaning-of-zero-matches)
    - [2B.6. Inspect version events explicitly, and state uncertainty](#2b-6-inspect-version-events-explicitly-and-state-uncertainty)
    - [2B.7. Dependency traversal and provenance checks for real sources](#2b-7-dependency-traversal-and-provenance-checks-for-real-sources)
- [Section 3 — Complete the exploration: validation, source discovery, history, graph-ready export](#section-3-complete-the-exploration-validation-source-discovery-history-graph-ready-export)
  - [3.1. Explicitly define the five kinds of correctness](#3-1-explicitly-define-the-five-kinds-of-correctness)
  - [3.2. Test our fixtures and source reads automatically](#3-2-test-our-fixtures-and-source-reads-automatically)
  - [3.3. Export graph-ready entities from **live PostgreSQL**](#3-3-export-graph-ready-entities-from-live-postgresql)
  - [3.4. Test repeatability, idempotency and historical change](#3-4-test-repeatability-idempotency-and-historical-change)
  - [3.5. Source discovery — make the pipeline extensible](#3-5-source-discovery-make-the-pipeline-extensible)
  - [3.6. Demonstrate bounded pagination and operational limits](#3-6-demonstrate-bounded-pagination-and-operational-limits)
    - [Final validation sign-off (first project *exploration* gate)](#final-validation-sign-off-first-project-exploration-gate)
- [Section 4 — Turn the exploratory proof into the bootcamp delivery](#section-4-turn-the-exploratory-proof-into-the-bootcamp-delivery)
  - [4.1. Planned tools mapped to our **actual** security data](#4-1-planned-tools-mapped-to-our-actual-security-data)
    - [4.2. Delivery architecture — what is built versus consumed](#4-2-delivery-architecture-what-is-built-versus-consumed)
    - [4.3. Sequential implementation backlog (half-day delivery gates)](#4-3-sequential-implementation-backlog-half-day-delivery-gates)
  - [4.4. Parallel work plan — **five half-days** from Monday afternoon to Wednesday afternoon](#4-4-parallel-work-plan-five-half-days-from-monday-afternoon-to-wednesday-afternoon)
    - [4.5. Suggested ownership and branch/interface agreements](#4-5-suggested-ownership-and-branch-interface-agreements)
    - [4.6. Minimum Wednesday acceptance (and what remains intentionally outside)](#4-6-minimum-wednesday-acceptance-and-what-remains-intentionally-outside)
- [Quick reference — commands to rerun with the team](#quick-reference-commands-to-rerun-with-the-team)
  - [References and continuity](#references-and-continuity)
- [Checkpoints Answers](#checkpoints-answers)

---


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="learning-map-and-four-acceptance-gates"></a>

## Learning map and four acceptance gates

| Gate | In plain English | What constitutes evidence? |
|---|---|---|
| **1 — SBOM ingestion** | Read a *Software Bill of Materials* (SBOM) and reconstruct an application's direct **and transitive** dependencies. | Component and edge counts, a traceable application → library path; no broken `bom-ref` references. |
| **2 — Source access** | Reliably fetch heterogeneous vulnerability intelligence (OSV, GitHub, CISA KEV) and an SBOM. | Successful responses, immutable bytes, hashes, source dates, pagination and rate-limit observations. |
| **3 — Version matching** | Connect a package **in the inventory** to a vulnerability **in the advisory**, and evaluate its version range correctly. | Affected, not affected, or **unknown** with regression cases; never infer safety from missing data. |
| **4 — Graph-ready knowledge** | Express applications, dependencies and vulnerabilities as named nodes and typed edges carrying evidence. | Stable IDs, paths, evidence hashes, correct changes after inventory updates; actual graph upload remains separate. |

**Central question:** *Which of our applications is affected by a newly disclosed vulnerability, through which dependencies, on what evidence, and did an upgrade resolve that exposure?*

Neither input source alone answers it. OSV describes affected packages; the SBOM describes used packages; the **join + version evaluation + dependency traversal** creates new, application-specific **knowledge**. A language model may explain the result later; it must not invent or decide deterministic version exposure.

---

<a id="section-1-understand-the-mechanism-using-tiny-fixtures"></a>

# Section 1 — Understand the mechanism using tiny fixtures


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="part-a-follow-the-entities-and-relationships-without-infrastructure-distractions"></a>

## Part A — Follow the entities and relationships, without infrastructure distractions


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="1a-1-read-a-software-bill-of-materials-sbom"></a>

### 1A.1. Read a Software Bill of Materials (SBOM)

A **CycloneDX** SBOM is a structured software inventory. These terms recur throughout this tutorial:

- **Application**: deployed software we care about, for example `Billing`.
- **Component**: a library/package included by that application.
- **`bom-ref`**: a reference **within one SBOM**. Think of it as a node key, not necessarily a globally unique package ID.
- **`purl`** (*Package URL*): ecosystem-aware package identifier, for example `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`.
- **`dependsOn`**: directed dependency links. If `A dependsOn B`, then `A → B`.

Our existing `data/fixtures/inventory_run1.json` describes:

```text
Application: Billing
  |
  | DEPENDS_ON (direct)
  v
billing-helper 1.0.0
  |
  | DEPENDS_ON (transitive from Billing)
  v
log4j-core 2.14.1
```

Read the **actual fixture**:

```bash
python -m json.tool data/fixtures/inventory_run1.json
```

The essential shape, shortened for clarity:

```json
{
  "metadata": {"component": {"bom-ref":"app:Billing", "name":"Billing"}},
  "components": [
    {"bom-ref":"pkg:billing-helper", "name":"billing-helper", "version":"1.0.0"},
    {"bom-ref":"pkg:log4j", "name":"log4j-core", "version":"2.14.1"}
  ],
  "dependencies": [
    {"ref":"app:Billing", "dependsOn":["pkg:billing-helper"]},
    {"ref":"pkg:billing-helper", "dependsOn":["pkg:log4j"]}
  ]
}
```

In the complete file, the Log4j component has `group` and `purl` fields, which will enable matching against an external advisory. **Exercise:** locate them. Explain why the `bom-ref` is useful for within-SBOM graph traversal but the `purl` is better for identifying packages across sources.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="1a-2-read-an-osv-advisory-a-different-perspective"></a>

### 1A.2. Read an OSV advisory — a different perspective

**OSV** = *Open Source Vulnerabilities* data format/service. Our `data/fixtures/osv_log4shell.json` contains a **reduced teaching interval** for Log4Shell:

```json
{
  "id": "CVE-2021-44228",
  "affected": [{
    "package": {"ecosystem":"Maven", "name":"org.apache.logging.log4j:log4j-core"},
    "ranges": [{"type":"ECOSYSTEM", "events":[
      {"introduced":"2.0-beta9"}, {"fixed":"2.15.0"}
    ]}]
  }]
}
```

- **CVE** = *Common Vulnerabilities and Exposures*, a vulnerability identifier, e.g. `CVE-2021-44228`.
- **Maven**: Java package ecosystem; its `group:artifact` coordinates identify a package.
- **Affected version range**: a rule, **not** an installed inventory. The abbreviated rule above is only for learning. Full live advisories can have several affected entries, events and exception cases.

Ask yourself: *Can this advisory alone tell us that `Billing` is vulnerable?* **No** — there is no application in the advisory.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="1a-3-join-two-perspectives-and-create-knowledge"></a>

### 1A.3. Join two perspectives and create knowledge

```text
SBOM (what Billing actually uses)
  Billing → billing-helper → log4j-core 2.14.1
                     +
OSV (which package versions are affected)
  Maven / org.apache.logging.log4j:log4j-core / CVE-2021-44228
                     ↓
ENTITY RESOLUTION: does group + artifact (Maven) match?
                     ↓
VERSION EVALUATION: is 2.14.1 in the affected interval?
                     ↓
NEW KNOWLEDGE:
Billing is affected through a transitive dependency,
with source evidence from both the inventory and the advisory.
```

**Why an ordinary SQL join is not enough:** joining a package to an advisory finds a *candidate*. A version-range evaluator decides whether that candidate is actually affected. A dependency traversal shows *why the application is exposed*. We retain the original evidence and the chain, rather than storing an unexplained Boolean.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="1a-4-model-the-other-two-source-types"></a>

### 1A.4. Model the other two source types

- **GHSA** = *GitHub Security Advisory*. `GHSA-jfh8-c2jp-5v3q` refers to the same CVE in our fixture. This is **alias/entity resolution**, not another installed component.
- **CISA KEV** = *Cybersecurity and Infrastructure Security Agency Known Exploited Vulnerabilities* catalogue. Its CVE entry contributes exploitation/prioritization context, **not** proof that any particular application contains a vulnerable package.
- A source may disagree or be updated; record **which source said what and when**, instead of discarding provenance.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="1a-5-simulate-change-remediation-and-history"></a>

### 1A.5. Simulate change: remediation and history

Read `data/fixtures/inventory_run2.json`: the same application now has `log4j-core 2.17.1`. In our bounded Log4Shell exercise:

| Snapshot | App | Log4j | Exposure to our selected interval | Interpretation |
|---|---|---|---|---|
| Run 1 | Billing | 2.14.1 | **affected** | The transitive dependency creates an exposure path. |
| Run 2 | Billing | 2.17.1 | **not affected** | That specific exposure path is resolved. |

This says **nothing** about vulnerabilities other than the selected CVE. **Knowledge changes when either an advisory or an inventory changes.** Keep both states rather than overwriting yesterday's conclusion.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="1a-6-from-rows-to-graph-ready-entities"></a>

### 1A.6. From rows to graph-ready entities

A graph has **nodes** (entities) and **edges** (typed relationships). Example:

```text
[Application: Billing]
       | DEPENDS_ON
       v
[Component: billing-helper@1.0.0]
       | DEPENDS_ON
       v
[Component: log4j-core@2.14.1]
       | AFFECTED_BY (matched range + evidence)
       v
[Vulnerability: CVE-2021-44228]
       | HAS_ALIAS
       v
[Advisory: GHSA-jfh8-c2jp-5v3q]
```

`HAS_ALIAS` is a **future design choice**, not an assertion that our existing fixture exporter emits this edge. What it already exports is described in §1B.

Design principles: stable IDs, directed relationships, **no `AFFECTED_BY` edge when status is `unknown`**, and source evidence for each derived conclusion. Decide whether an edge means *current state* or *historical state* before synchronizing any external graph later.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="checkpoint-1a-write-three-sentences-before-running-code"></a>

### Checkpoint 1A — Write three sentences before running code

1. **Data**: what factual claim comes from OSV? What factual claim comes from the SBOM?
2. **Knowledge**: which operation connects them, and why is transitive traversal essential?
3. **Evidence**: what should we save to reproduce the conclusion next week?


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="part-b-execute-the-fixture-demonstration-with-sqlite-no-server"></a>

## Part B — Execute the fixture demonstration with SQLite (no server)

**Why SQLite here?** We want to understand the *same logical entities* that eventually live in BigQuery and PostgreSQL, without configuring database users, network ports or Docker. Python has a built-in `sqlite3` module; the optional `sqlite3` command-line interface (CLI) makes the result visible immediately. **We switch to PostgreSQL only in Section 2**, when we download and actively transform real data.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="1b-1-set-up-the-google-vm-and-poetry"></a>

### 1B.1. Set up the Google VM and Poetry

Open VS Code Remote-SSH to your own Google VM (Ubuntu/Debian assumed). Place the companion ZIP in your home folder (VS Code remote Explorer or `scp` from the Mac) and extract it; use a personal checkout, not a shared mutable directory.

```bash
sudo apt-get update
sudo apt-get install -y unzip sqlite3
mkdir -p ~/code && cd ~/code
unzip -q ~/knowledge_protocol_validation_team_code.zip
cd knowledge_protocol_validation_team_code
python3 --version
poetry --version
sqlite3 --version
```

If the ZIP has a different filename/location, substitute it. The exercises target Python **3.12** (as in our Le Wagon VM). The companion already contains `pyproject.toml`; do **not** run `poetry init` over it:

```bash
poetry env use python3.12
poetry install
poetry run python --version
poetry run python -c 'import sqlite3; print(sqlite3.sqlite_version)'
```

If `poetry` is absent, follow your bootcamp's normal installation/setup process, then retry; do not silently replace the team workflow with global `pip install`.

**On macOS** (instead of `apt-get`): install the CLI with `brew install sqlite` if needed (Homebrew may install it as `$(brew --prefix sqlite)/bin/sqlite3`); macOS may already provide `/usr/bin/sqlite3`. Use the same Poetry commands. For python.org 3.14, a missing CA bundle previously caused HTTPS failures; Section 2 explains the certificate fix. We prefer Python 3.12 for the team exercises.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="1b-2-run-the-existing-curated-fixture-pipeline"></a>

### 1B.2. Run the *existing* curated fixture pipeline

Before reading the implementation, predict the expected result: Billing → billing-helper → Log4j 2.14.1 is affected by the **teaching interval**; in run 2, Billing uses 2.17.1 and that particular exposure disappears.

```bash
poetry run python src/validate.py
poetry run python -m unittest discover -s tests -v
ls -lh data/outputs/
```

The script creates `data/outputs/validation.sqlite`, two snapshots of graph-ready JSON nodes/edges, and `results.json`. The historical local run produced five source snapshots, two dependency edges in run 1, four graph nodes and three edges for run 1, then four nodes and two edges for run 2; its two unit tests passed. **Those are fixture baseline observations, not live ingestion results.**

**Where the code creates knowledge** (`src/validate.py`):

1. `store(...)` reads each fixture's original bytes, calculates SHA-256, and records a source snapshot. This is our small **Bronze** analogue: source provenance precedes transformations.
2. `inventory(...)` checks the CycloneDX SBOM, collects components and `DEPENDS_ON` edges, and traverses from the application to reachable libraries. These normalized rows are our **Silver** analogue.
3. The OSV advisory is normalized to package and version-range fields, and its CVE/GHSA alias relationships are checked.
4. The code joins *Maven ecosystem + package identity*, then evaluates the installed version using `affected(...)`. Only this combination and a dependency path establishes a derived application exposure. This is our **Gold knowledge** analogue.
5. `export_graph(...)` emits node/edge JSON with source evidence for later use by a knowledge graph. No VPS/API is required or contacted.

`affected(...)` is a deliberately **restricted fixture comparator**. It is *not* the full Maven `ComparableVersion` algorithm and must return `unknown` for unsupported cases. The fixture's `2.15.0` boundary is illustrative; do not use it as a complete authoritative Log4Shell advisory range.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="1b-3-explore-the-database-using-the-sqlite-cli"></a>

### 1B.3. Explore the database using the SQLite CLI

```bash
sqlite3 data/outputs/validation.sqlite
```

At the `sqlite>` prompt, run:

```sql
.headers on
.mode column
.tables
.schema exposures
SELECT run_id, app, package_name, version, status FROM exposures ORDER BY run_id;
```

**Look for:** `Billing`, `2.14.1`, `affected` in run 1 and `2.17.1`, `not_affected` in run 2. The word `exposure` names the *derived* entity: the source files did not contain this conclusion. Quit with `.quit`.

These ready-to-run one-line commands are convenient for screenshots and reproducible evidence:

```bash
sqlite3 -header -column data/outputs/validation.sqlite \
 'SELECT run_id, app, bom_ref, package_name, version FROM inventory_components ORDER BY run_id, app, bom_ref;'

sqlite3 -header -column data/outputs/validation.sqlite \
 'SELECT run_id, app, parent_ref, child_ref FROM dependencies ORDER BY run_id, app, parent_ref;'

sqlite3 -header -column data/outputs/validation.sqlite \
 'SELECT vuln_id, ecosystem, package_name, introduced, fixed FROM vulnerabilities;'
```

Identify what each relation means: a `component` is a package instance in an inventory; a `dependency` is a directed edge between two SBOM `bom-ref`s; a `vulnerability` is an external advisory; an `exposure` is **new knowledge**, computed from those entities.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="1b-4-use-sql-to-reveal-direct-and-transitive-relationships"></a>

### 1B.4. Use SQL to reveal direct and transitive relationships

Run the bundled query file:

```bash
sqlite3 -header -column data/outputs/validation.sqlite < sql/validation_queries.sql
```

Read its recursive CTE (`WITH RECURSIVE walk AS ...`): the anchor starts at `app:Billing`; the recursive part follows `parent_ref → child_ref`; the `depth < 20` and visited-path check bound recursion and reduce cycles. The path reaches `pkg:log4j` at depth 2; this is why simply listing libraries is weaker than reconstructing transitive **dependency paths**.

Compare the two runs with a second query:

```sql
SELECT a.app, a.version AS before_version, b.version AS after_version,
       a.status AS before_status, b.status AS after_status
FROM exposures a
JOIN exposures b ON a.app=b.app AND a.package_name=b.package_name
 AND a.vuln_id=b.vuln_id
WHERE a.run_id=1 AND b.run_id=2;
```

This is *historical change*. An `UPDATE` that overwrote run 1 would destroy the evidence that Billing was previously exposed. In the production system we will make history retention explicit.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="1b-5-inspect-the-graph-ready-knowledge-without-a-graph-server"></a>

### 1B.5. Inspect the graph-ready knowledge without a graph server

```bash
poetry run python -m json.tool data/outputs/graph_nodes_run1.json
poetry run python -m json.tool data/outputs/graph_edges_run1.json
poetry run python -m json.tool data/outputs/graph_edges_run2.json
```

Find `DEPENDS_ON` (inventory evidence) and `AFFECTED_BY` (matching against the advisory). Run 1 includes an `AFFECTED_BY` edge; run 2 omits it because the **selected** vulnerability range no longer matches. The edge's `evidence_sha256` points back to the source used to justify the assertion. Graph-ready files are *data products*, not yet the Neo4j knowledge graph.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="1b-6-validate-and-interpret-what-idempotency-means-here"></a>

### 1B.6. Validate and interpret what *idempotency* means here

```bash
poetry run python src/validate.py
poetry run python src/validate.py
poetry run python -m unittest discover -s tests -v
sqlite3 data/outputs/validation.sqlite 'PRAGMA integrity_check;'
sqlite3 data/outputs/validation.sqlite 'PRAGMA foreign_key_check;'
```

The fixture script **recreates** its SQLite file each time. Repeatable logical results demonstrate *reproducibility*, but not yet production **idempotent upserts**. In Section 3 we will discuss `ON CONFLICT`, content-hash snapshot deduplication, immutable Bronze objects, and what it means to run the same Airflow task twice without duplicating facts.

**Checkpoint 1B — write your own values, not just the expected ones:**

| Observation | Expected learning | Your result / command |
|---|---|---|
| Run 1 exposure | Billing affected by selected CVE | ___ |
| Dependency depth | Two hops to Log4j | ___ |
| Run 2 | Specific exposure no longer active | ___ |
| Graph export | Typed nodes/edges + evidence hashes | ___ |
| Integrity and rerun | No foreign-key violations; results reproducible | ___ |

**Pause here:** without installing PostgreSQL, you should be able to explain the path **SBOM → package identity + OSV → version check → application exposure → graph-ready relation**. Next, reproduce this reasoning on **real** downloaded records and a PostgreSQL database.

---

<a id="section-2-retrieve-real-source-data-and-build-a-second-honest-proof"></a>

# Section 2 — Retrieve real source data and build a second, honest proof


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="part-a-choose-a-coherent-dataset-before-downloading-anything"></a>

## Part A — Choose a coherent dataset before downloading anything


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="2-0-switch-to-postgresql-for-the-real-data-laboratory"></a>

## 2.0. Switch to PostgreSQL for the real-data laboratory

We now *actively code* normalization for real OSV/GHSA/KEV/CycloneDX records. PostgreSQL is a better fit for this second step: we can retain complex source structures in `JSONB`, use relational constraints/joins, and later map the same models to BigQuery/dbt. **Do not migrate the fixture SQLite file**: it remains the controlled reference for comparison.

On your Google VM, start the **isolated Docker Compose** PostgreSQL 14 service supplied in the companion package. Use port `5433` on the VM host (container internal port `5432`), leaving any pre-existing PostgreSQL service alone:

```bash
command -v docker && docker compose version
export DATABASE_URL='postgresql://knowledge:tutorial_local_only@127.0.0.1:5433/knowledge_lab'
docker compose -f docker-compose.tutorial.yml up -d
docker compose -f docker-compose.tutorial.yml exec -T postgres \
  pg_isready -U knowledge -d knowledge_lab
docker compose -f docker-compose.tutorial.yml exec -T postgres \
  psql -v ON_ERROR_STOP=1 -U knowledge -d knowledge_lab < sql/pg_live.sql
```

Check the connection and the `live` schema:

```bash
docker compose -f docker-compose.tutorial.yml exec -T postgres \
  psql -U knowledge -d knowledge_lab -c '\dn'
```

`psql` runs **inside** the container; the VM does not need a host PostgreSQL client. You may use DBeaver on your Mac through **VS Code Remote-SSH port forwarding** for the VM port 5433, if desired; do not expose PostgreSQL publicly. If port `5433` is occupied, change only the *left-hand* mapping in Compose and the corresponding `DATABASE_URL` host port. These credentials are intentionally tutorial-only: do not reuse them for deployed services.

**PostgreSQL ⇔ SQLite continuity:** `inventory_components` → `live.sbom_components`; `dependencies` → `live.sbom_edges`; `vulnerabilities` → `live.osv_affected`; `snapshots` → `live.snapshots`. We still need a **version evaluator** before creating trustworthy `AFFECTED_BY` results from live data.



<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="2a-1-a-minimal-proof-of-concept-question-determines-the-sources"></a>

### 2A.1. A minimal *proof-of-concept question* determines the sources

**Question:** *Given a known Log4Shell advisory and an SBOM inventory, can we determine whether a particular application includes an affected version and show the evidence?*

Start with a **small connected scenario**, not a large random dataset. You need five things:

1. A real **advisory** carrying affected package identifiers and version-range events (OSV).
2. A second advisory for **identity cross-checking** (GitHub GHSA ↔ CVE).
3. A prioritization signal for **enrichment**, when present (CISA KEV).
4. An **SBOM with dependencies** to test traversal (CycloneDX).
5. A **matching application inventory**, if we want a demonstrable exposure join; the public CycloneDX *CBOM* example is **not guaranteed** to contain the Maven Log4j package. For this bounded validation, retain our **explicitly synthetic** Billing inventory as the matching control.

These are two different assertions: **A)** real sources can be retrieved and normalized, and **B)** a known test inventory matches a real advisory. Do not conflate them. Later, the team should seek authorized, representative enterprise SBOMs or generate genuine SBOMs from an open-source Java project with a pinned Log4j dependency.

**Data-selection questions for each potential new source**:

| Decision | Question | Good answer for this POC |
|---|---|---|
| Entity overlap | Which keys connect datasets? | CVE ↔ GHSA; Maven `group:artifact` ↔ SBOM PURL |
| Shape | JSON list, JSON object, paginated API, complete catalogue? | One record + one bounded page + one full feed |
| Version semantics | Are affected ranges structured and testable? | OSV `affected[].ranges[].events[]` |
| Dependency detail | Does the inventory contain a root and `dependsOn` references? | CycloneDX `metadata.component` + `dependencies[]` |
| Provenance | Can we retain URL, timestamp, hashes and source version? | HTTP headers + SHA-256 + immutable stored bytes |
| Reproducibility | Can a teammate rerun it without credentials? | Public HTTPS endpoints, capped responses |
| Ethics/security | Do we have permission to use the inventory? | Synthetic/public for POC; private SBOMs remain private |
| Extension | Can we grow from 1 CVE to many without changing semantics? | Yes, normalized keys and range events |

**Choose your own extension:** add a *second CVE* with a **different interval shape** (for instance multiple events) rather than merely adding 1,000 similar records. This reveals parser weaknesses early. Record the CVE, package, expected known affected/unaffected versions and source reference in the evidence table.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="2a-2-run-the-previously-tested-downloader"></a>

### 2A.2. Run the previously tested downloader

From the repository root on the GCP VM:

```bash
poetry run python src/fetch_live.py
ls -lh data/raw/
poetry run python -m json.tool data/raw/live_manifest.json | head -n 90
```

The earlier Mac execution on **22 November 2026** returned HTTP 200 for all five source requests:

| Source | Earlier observed bytes | Expected file | Why useful |
|---|---:|---|---|
| OSV Log4Shell | 112,802 | `osv_log4shell.json` | Detailed real affected package ranges |
| GitHub GHSA Log4Shell | 12,791 | `github_log4shell.json` | CVE ↔ GHSA identity, advisory attributes |
| GitHub advisories page 1 | 52,555 | `github_advisories_page1.json` | Pagination / list behavior (`Link: rel="next"`) |
| CISA KEV | 1,871,127 | `cisa_kev.json` | Full known-exploitation catalogue |
| CycloneDX example | 1,542 | `cyclonedx_dependencies.json` | Public dependency graph example (CBOM) |

Total response payloads: **2,050,817 bytes (~1.96 MiB)**. This is a *historical observation from the provided manifest*, **not** a promise that today's files or response headers are byte-identical. A ~2 MiB raw directory is expected for this narrow trial; KEV accounts for most of it.

> **macOS certificate lesson (already encountered):** The python.org Python 3.14 installation had `cafile=None`, causing `CERTIFICATE_VERIFY_FAILED` for all five endpoints. Running `open "/Applications/Python 3.14/Install Certificates.command"` corrected the CA trust setup. VM Python 3.12 may already have working CA certificates; if not, diagnose with `python -c 'import ssl; print(ssl.get_default_verify_paths())'`, OS CA packages, and proxy policy. **Never** use `verify=False` or an unverified SSL context.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="2a-3-understand-the-manifest-not-just-the-json"></a>

### 2A.3. Understand the **manifest**, not just the JSON

A **manifest** is an ingestion logbook: what source was requested, when, what HTTP status and metadata it returned, and the SHA-256 fingerprint of the original bytes.

```bash
poetry run python - <<'PY'
import json
from pathlib import Path
manifest=json.loads(Path('data/raw/live_manifest.json').read_text())
for x in manifest:
    print(x['name'], x['status'], x.get('status_code'),
          x.get('bytes'), (x.get('sha256') or '')[:12],
          bool(x.get('link_header')))
PY
```

`sha256` is a content identity; **ETag** and **Last-Modified** are HTTP update hints, not universally guaranteed or interchangeable with content hashes. `retrieved_utc` is **our ingestion time**, not the vulnerability's publication date. A hash change may reflect ordering/metadata rather than meaningful knowledge changes; semantic change detection comes later.

**Run the source-integrity test:**

```bash
poetry run python - <<'PY'
import hashlib, json
from pathlib import Path
root=Path('data/raw')
for r in json.loads((root/'live_manifest.json').read_text()):
    if r['status']!='downloaded':
        print(r['name'], 'NOT DOWNLOADED', r.get('error')); continue
    f=root/(r['name']+'.json')
    print(r['name'],
          'PASS' if hashlib.sha256(f.read_bytes()).hexdigest()==r['sha256'] else 'FAIL')
PY
```

Expected for a successful unchanged capture: five `PASS` values. If a file is modified after fetching, it should fail — this is desirable. **Production rule:** timestamp/version every snapshot and retain a pointer to its object path. The current tutorial downloader writes to fixed filenames and overwrites them on later runs; snapshot immutability is a **planned correction**, not a feature already provided.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="2a-4-explore-the-five-json-files-learn-the-schemas-with-tiny-commands"></a>

### 2A.4. Explore the five JSON files — learn the schemas with tiny commands

**OSV (which package/ranges are affected):**

```bash
poetry run python - <<'PY'
import json
x=json.load(open('data/raw/osv_log4shell.json'))
print('id',x['id'],'affected entries',len(x.get('affected',[])))
for i,a in enumerate(x.get('affected',[])):
    print(i,a.get('package'), 'range types',
          [r.get('type') for r in a.get('ranges',[])],
          'explicit versions',len(a.get('versions',[])))
PY
```

**CycloneDX (what the inventory contains):**

```bash
poetry run python - <<'PY'
import json
x=json.load(open('data/raw/cyclonedx_dependencies.json'))
print(x['bomFormat'],x['specVersion'])
print('components',len(x.get('components',[])),
      'dependency records',len(x.get('dependencies',[])))
for c in x.get('components',[]):
    print(c.get('bom-ref'),c.get('name'),c.get('version'),c.get('purl'))
for d in x.get('dependencies',[]):
    print('EDGE',d.get('ref'),'→',d.get('dependsOn',[]))
PY
```

**GitHub (same CVE, different advisory ID):**

```bash
poetry run python - <<'PY'
import json
x=json.load(open('data/raw/github_log4shell.json'))
print(x.get('ghsa_id'), '↔', x.get('cve_id'),
      'severity',x.get('severity'),
      'affected packages',len(x.get('vulnerabilities',[])))
PY
```

**CISA KEV (enrichment by CVE):**

```bash
poetry run python - <<'PY'
import json
x=json.load(open('data/raw/cisa_kev.json'))
rows=[r for r in x.get('vulnerabilities',[])
      if r.get('cveID')=='CVE-2021-44228']
print('Total KEV records',len(x.get('vulnerabilities',[])))
print('Matching CVE records',len(rows))
for r in rows: print(r)
PY
```

**GitHub listing (pagination):**

```bash
poetry run python - <<'PY'
import json
from pathlib import Path
x=json.loads(Path('data/raw/github_advisories_page1.json').read_text())
m=json.loads(Path('data/raw/live_manifest.json').read_text())
print('Advisories in first page:',len(x))
print('First IDs:',[a.get('ghsa_id') for a in x])
print('Next link:',next(r['link_header'] for r in m
                         if r['name']=='github_advisories_page1'))
PY
```

A `Link: rel="next"` tells us there are more results; **do not assume** sequential `page=2` always works, because the observed API link used a cursor (`after=...`). In production follow the **server-supplied** next URL within an allowlisted API host, with a page cap and rate limit handling.

**Checkpoint 2A — Copy, fill, and briefly explain:**

| Source | HTTP | Size | SHA prefix | Entity key found | Next/change mechanism | My observation |
|---|---|---:|---|---|---|---|
| OSV | ___ | ___ | ___ | CVE + package | modified/hash | ___ |
| GHSA | ___ | ___ | ___ | GHSA ↔ CVE | update/ETag | ___ |
| GHSA list | ___ | ___ | ___ | GHSA | Link next/cursor | ___ |
| KEV | ___ | ___ | ___ | CVE | full-feed refresh | ___ |
| CycloneDX | ___ | ___ | ___ | `bom-ref` / `purl` | source commit/hash | ___ |

**Hints:** values come from `live_manifest.json`, except the entity keys, which you identify inside JSON. HTTP 200 proves access, *not* semantic correctness or complete ingestion. Document unexpected nulls and schema variations.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="part-b-normalize-real-data-into-postgresql-query-the-relationships-test-claims"></a>

## Part B — Normalize real data into PostgreSQL, query the relationships, test claims


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="2b-1-first-make-the-target-relational-model-explicit"></a>

### 2B.1. First make the target relational model explicit

```text
Source snapshot ──EVIDENCE_FOR──> affected-package record
       |                                  |
       |                                  | SAME_PACKAGE (ecosystem + coordinates)
       |                                  v
SBOM inventory ──CONTAINS──> component@version
       |                                  |
       └── DEPENDS_ON edges ──────────────┘
                                          |
                                  VERSION_MATCH evaluation
                                          v
                               Exposure (affected / not / unknown)
```

We normalize data **without prematurely flattening away** the OSV `ranges[]`/`events[]` structures. In this learning lab we store those as PostgreSQL **JSONB** so they can be inspected. Later, Silver can also break the events into typed rows for scale and easier quality testing.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="2b-2-extend-postgresql-with-a-live-source-schema"></a>

### 2B.2. Extend PostgreSQL with a live-source schema

Use a **separate schema** so real observations and teaching fixtures never get confused. Create `sql/pg_live.sql`:

```sql
CREATE SCHEMA IF NOT EXISTS live;

CREATE TABLE IF NOT EXISTS live.snapshots (
  source_name TEXT PRIMARY KEY,
  source_url TEXT NOT NULL,
  retrieved_utc TIMESTAMPTZ NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS live.osv_affected (
  source_name TEXT NOT NULL REFERENCES live.snapshots(source_name),
  cve_id TEXT NOT NULL,
  affected_index INTEGER NOT NULL,
  ecosystem TEXT,
  package_name TEXT,
  ranges JSONB NOT NULL,
  explicit_versions JSONB NOT NULL,
  PRIMARY KEY (source_name,affected_index)
);

CREATE TABLE IF NOT EXISTS live.sbom_components (
  bom_ref TEXT PRIMARY KEY,
  component_name TEXT NOT NULL,
  component_group TEXT,
  version TEXT,
  purl TEXT,
  component_type TEXT
);

CREATE TABLE IF NOT EXISTS live.sbom_edges (
  parent_ref TEXT NOT NULL REFERENCES live.sbom_components(bom_ref),
  child_ref TEXT NOT NULL REFERENCES live.sbom_components(bom_ref),
  PRIMARY KEY (parent_ref,child_ref)
);

CREATE TABLE IF NOT EXISTS live.advisory_aliases (
  source_name TEXT NOT NULL REFERENCES live.snapshots(source_name),
  cve_id TEXT NOT NULL,
  alias_id TEXT NOT NULL,
  PRIMARY KEY (source_name,cve_id,alias_id)
);
```

```bash
docker compose -f docker-compose.tutorial.yml exec -T postgres \
  psql -v ON_ERROR_STOP=1 -U knowledge -d knowledge_lab < sql/pg_live.sql
```


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="2b-3-write-the-live-loader-read-local-raw-json-never-refetch-inside-transformations"></a>

### 2B.3. Write the live loader (read local raw JSON, never refetch inside transformations)

Create `src/load_live_pg.py`:

```python
import hashlib
import json
import os
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'data' / 'raw'
manifest = json.loads((RAW / 'live_manifest.json').read_text())


def file_for(r):
    raw = (RAW / (r['name'] + '.json')).read_bytes()
    if hashlib.sha256(raw).hexdigest() != r['sha256']:
        raise ValueError('SHA-256 mismatch: ' + r['name'])
    return json.loads(raw)


with psycopg.connect(os.environ['DATABASE_URL']) as conn:
    with conn.cursor() as cur:
        # REPLACE only this disposable lab schema, never raw files or lab fixtures.
        cur.execute('TRUNCATE live.advisory_aliases,live.sbom_edges, '
                    'live.sbom_components,live.osv_affected,live.snapshots CASCADE')
        docs = {}
        for r in manifest:
            if r['status'] != 'downloaded':
                continue
            obj = file_for(r)
            docs[r['name']] = obj
            cur.execute('INSERT INTO live.snapshots VALUES (%s,%s,%s,%s,%s,%s)',
                        (r['name'],r['url'],r['retrieved_utc'],r['sha256'],
                         r['bytes'],Jsonb(obj)))

        osv = docs['osv_log4shell']
        for i,a in enumerate(osv.get('affected', [])):
            p=a.get('package') or {}
            cur.execute('INSERT INTO live.osv_affected VALUES '
                        '(%s,%s,%s,%s,%s,%s,%s)',
                        ('osv_log4shell',osv['id'],i,p.get('ecosystem'),
                         p.get('name'),Jsonb(a.get('ranges',[])),
                         Jsonb(a.get('versions',[]))))

        bom=docs['cyclonedx_dependencies']
        if bom.get('bomFormat') != 'CycloneDX':
            raise ValueError('Not a CycloneDX document')
        root=bom.get('metadata',{}).get('component')
        components=([root] if root and root.get('bom-ref') else [])+bom.get('components',[])
        refs=[c['bom-ref'] for c in components]
        if len(refs)!=len(set(refs)):
            raise ValueError('Duplicate bom-ref')
        for c in components:
            cur.execute('INSERT INTO live.sbom_components VALUES '
                        '(%s,%s,%s,%s,%s,%s)',
                        (c['bom-ref'],c.get('name',''),c.get('group'),
                         c.get('version'),c.get('purl'),c.get('type')))
        for d in bom.get('dependencies',[]):
            if d['ref'] not in refs:
                raise ValueError('Unresolved dependency parent: '+d['ref'])
            for child in d.get('dependsOn',[]):
                if child not in refs:
                    raise ValueError('Unresolved dependency child: '+child)
                cur.execute('INSERT INTO live.sbom_edges VALUES (%s,%s)',
                            (d['ref'],child))

        gh=docs['github_log4shell']
        if gh.get('cve_id') and gh.get('ghsa_id'):
            cur.execute('INSERT INTO live.advisory_aliases VALUES (%s,%s,%s)',
                        ('github_log4shell',gh['cve_id'],gh['ghsa_id']))
        kev=docs['cisa_kev']
        for v in kev.get('vulnerabilities',[]):
            if v.get('cveID') == osv['id']:
                cur.execute('INSERT INTO live.advisory_aliases VALUES (%s,%s,%s)',
                            ('cisa_kev',v['cveID'],'CISA-KEV'))

print('Real-source JSON normalized into live.*')
```

```bash
poetry run python src/load_live_pg.py
```

If it fails on an unexpected CycloneDX reference or structure, **do not silently skip records**. Capture the problem, inspect that raw JSON path and decide whether to (a) support this schema variant, or (b) choose a simpler SBOM with an explicit source justification. The `live.*` schema represents **one bounded snapshot**, not yet general multi-run historical ingestion.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="2b-4-query-source-identities-and-dependencies"></a>

### 2B.4. Query source identities and dependencies

Run the following from `psql` (or save in `sql/pg_live_queries.sql`):

```sql
-- How much data did we normalize? Compare with manifest.
SELECT source_name,size_bytes,left(sha256,12) AS hash
FROM live.snapshots ORDER BY source_name;

-- What distinct package coordinates are described by OSV?
SELECT cve_id,ecosystem,package_name,
       jsonb_array_length(ranges) AS range_count
FROM live.osv_affected;

-- How is this SBOM connected?
SELECT p.component_name AS parent, c.component_name AS child
FROM live.sbom_edges e
JOIN live.sbom_components p ON p.bom_ref=e.parent_ref
JOIN live.sbom_components c ON c.bom_ref=e.child_ref;

-- Which source says which alias?
SELECT * FROM live.advisory_aliases;
```

**SQL relationship questions:** Why is the edge table not sufficient without `components`? Why is a CVE-to-GHSA alias a different kind of relation from `DEPENDS_ON`? Which source hash supports a claim, and where is that hash stored?


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="2b-5-try-a-real-package-join-understand-the-meaning-of-zero-matches"></a>

### 2B.5. Try a real package join — understand the meaning of zero matches

```sql
SELECT s.component_name,s.version,s.purl,o.cve_id,o.package_name
FROM live.sbom_components s
JOIN live.osv_affected o
 ON lower(o.ecosystem)='maven'
AND s.purl LIKE 'pkg:maven/%'
AND (s.component_group || ':' || s.component_name)=o.package_name;
```

**Zero matches is a legitimate outcome.** The public CBOM sample was chosen to illustrate dependency structure, *not* guaranteed to include `org.apache.logging.log4j:log4j-core`. A zero-row join proves neither that a business is safe nor that our join code is broken. It means the selected datasets do not intersect on these keys.

For a positive **controlled** cross-source test, create two **inline synthetic Billing inventory rows** using SQL `VALUES`, and join them to the **real OSV advisory** in `live.osv_affected`. This makes it clear which side is simulated and does not require a PostgreSQL fixture schema:

```sql
WITH simulated_inventory(inventory_run, app, ecosystem, package_name, installed_version) AS (
    VALUES
      (1, 'Billing', 'Maven', 'org.apache.logging.log4j:log4j-core', '2.14.1'),
      (2, 'Billing', 'Maven', 'org.apache.logging.log4j:log4j-core', '2.17.1')
)
SELECT c.inventory_run, c.app, c.installed_version,
       o.cve_id, o.package_name, o.ranges
FROM simulated_inventory c
JOIN live.osv_affected o
  ON lower(c.ecosystem) = lower(o.ecosystem)
 AND c.package_name = o.package_name
ORDER BY c.inventory_run;
```

This is *real advisory + simulated enterprise installation*. Label the conclusion **controlled**, not real enterprise exposure. The JOIN creates only candidates; it does **not** yet interpret the full advisory interval.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="2b-6-inspect-version-events-explicitly-and-state-uncertainty"></a>

### 2B.6. Inspect version events explicitly, and state uncertainty

```sql
SELECT a.cve_id,a.package_name,
       rng ->> 'type' AS range_type,
       rng -> 'events' AS events
FROM live.osv_affected a
CROSS JOIN LATERAL jsonb_array_elements(a.ranges) AS rng;
```

OSV may express multiple ranges, `introduced`, `fixed`, `last_affected`, `limit`, `versions`, and qualifiers. **Do not** implement Maven comparisons using string sorting, Python's `packaging.version`, or a single `version < fixed` check. A complete matcher must handle Maven's release qualification semantics and test the exact affected entries from the advisory. Until then, record `unknown`, **not** `not_affected`, for unsupported variants.

Our bounded fixture matcher in `src/validate.py` tests five teaching cases: `2.14.1` affected; `2.15.0` and `2.17.1` not affected **within the reduced interval**; `2.0.0` and `2.14.1-SNAPSHOT` unknown. **These do not certify the live full OSV advisory.** Full parser and golden test cases are a production blocker, assigned in Section 4.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="2b-7-dependency-traversal-and-provenance-checks-for-real-sources"></a>

### 2B.7. Dependency traversal and provenance checks for real sources

To traverse the **public SBOM** instead of the fixture:

```sql
WITH RECURSIVE roots AS (
  SELECT c.bom_ref,c.component_name
  FROM live.sbom_components c
  WHERE NOT EXISTS (
    SELECT 1 FROM live.sbom_edges e WHERE e.child_ref=c.bom_ref
  )
), walk AS (
  SELECT r.bom_ref AS root_ref,r.bom_ref,r.component_name,
         0 AS depth, ARRAY[r.bom_ref]::TEXT[] AS seen
  FROM roots r
  UNION ALL
  SELECT w.root_ref,c.bom_ref,c.component_name,w.depth+1,w.seen||c.bom_ref
  FROM walk w
  JOIN live.sbom_edges e ON e.parent_ref=w.bom_ref
  JOIN live.sbom_components c ON c.bom_ref=e.child_ref
  WHERE w.depth<20 AND NOT c.bom_ref=ANY(w.seen)
)
SELECT root_ref,component_name,depth FROM walk ORDER BY root_ref,depth;
```

A graph may have several roots or disconnected parts; record this instead of forcing a single application node. Our script already checks `bom-ref` duplicates and missing edge endpoints.

**Checkpoint 2B — Run log embedded in the tutorial:**

| Validation | SQL/command | My output | Interpretation or next fix |
|---|---|---|---|
| SHA-256 integrity | §2A.3 Python | ___ | Any mismatch? |
| Source row count | `SELECT COUNT(*) FROM live.snapshots;` | ___ | Expect 5 if all fetched |
| OSV affected packages | `SELECT COUNT(*) FROM live.osv_affected;` | ___ | May be more than one |
| Public SBOM nodes/edges | `COUNT(*)` on `live.sbom_components`, `live.sbom_edges` | ___ | What graph structure? |
| Alias join | `SELECT * FROM live.advisory_aliases;` | ___ | GHSA ↔ CVE; KEV signal |
| Public SBOM ↔ OSV | §2B.5 query | ___ | Zero can be valid |
| Synthetic Billing ↔ real OSV | §2B.5 query | ___ | Candidates, not yet exposure |
| Full Maven interval evaluator | §2B.6 | **PENDING** | Do not claim production correctness |

---

<a id="section-3-complete-the-exploration-validation-source-discovery-history-graph-ready-export"></a>

# Section 3 — Complete the exploration: validation, source discovery, history, graph-ready export


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="3-1-explicitly-define-the-five-kinds-of-correctness"></a>

## 3.1. Explicitly define the five kinds of correctness

| Concern | Example validation | When it should run |
|---|---|---|
| **Acquisition** | HTTP status, payload size cap, SHA-256 verification, JSON parseability | Immediately on download → Bronze |
| **Structural** | CycloneDX format, unique `bom-ref`, no dangling dependency edges | Before Silver insertion |
| **Identity** | Normalize Maven `group:artifact` and PURL; verified CVE ↔ GHSA alias | During Silver normalization |
| **Semantic** | Correct Maven ranges, transitive exposure and `unknown` policy | Before Gold publication |
| **Operational** | Idempotent replay, source freshness, failed-source alerts, history retention | Every scheduled run / CI |

**Important:** `TRUNCATE` in our teaching loader makes it easy to re-run one temporary snapshot, but it **destroys history**. Production must use append-only raw snapshots, stable keys, upserts and separate current/history models. Use deliberately timestamped replay tests, not just a fresh reset.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="3-2-test-our-fixtures-and-source-reads-automatically"></a>

## 3.2. Test our fixtures and source reads automatically

Create `tests/test_data_contract.py`:

```python
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FIX=ROOT/'data'/'fixtures'


def test_inventory_references_resolve():
    bom=json.loads((FIX/'inventory_run1.json').read_text())
    assert bom['bomFormat']=='CycloneDX'
    comps=[bom['metadata']['component']]+bom['components']
    refs={c['bom-ref'] for c in comps}
    assert len(refs)==len(comps)
    for edge in bom['dependencies']:
        assert edge['ref'] in refs
        assert set(edge.get('dependsOn',[])) <= refs


def test_fixture_package_matches_osv():
    bom=json.loads((FIX/'inventory_run1.json').read_text())
    osv=json.loads((FIX/'osv_log4shell.json').read_text())
    c=next(c for c in bom['components'] if c['name']=='log4j-core')
    package=next(a['package'] for a in osv['affected']
                 if a['package']['ecosystem']=='Maven')
    assert c['group']+':'+c['name']==package['name']
```

```bash
poetry run pytest -q
```

Add tests for (a) missing `bom-ref`, (b) duplicate references, (c) malformed versions, (d) no-match scenarios, (e) range exceptions and (f) invalid hashes. **Fail closed or yield `unknown`** for ambiguous version-matching states; record the reason.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="3-3-export-graph-ready-entities-from-live-postgresql"></a>

## 3.3. Export graph-ready entities from **live PostgreSQL**

Section 1 already demonstrated an affected path in a small, controlled SQLite case. Now `src/export_pg_graph.py` exports the actual public CycloneDX *dependency* nodes/edges stored in `live.sbom_components` and `live.sbom_edges`. The export deliberately **does not invent** `AFFECTED_BY` edges; the public CBOM need not contain Log4j, and the full Maven matcher is not yet implemented.

```bash
poetry run python src/export_pg_graph.py
poetry run python -m json.tool data/outputs/pg_graph_nodes_live.json
poetry run python -m json.tool data/outputs/pg_graph_edges_live.json
```

Check that every edge's `source` and `target` exists in the node list, and that each relationship is directed correctly. The exporter names each node with its SBOM-specific reference and records its original source hash. These IDs are for *one captured inventory*, not globally stable enterprise entity IDs. In production, define tenant, inventory and component identity explicitly; distinguish current edges from history, and document synchronization/removal semantics before sending anything to VPS/Neo4j.

**Checkpoint 3.3:**

| Check | Evidence | Result |
|---|---|---|
| Valid graph endpoints | No edge points to a missing node | ___ |
| Dependencies | `DEPENDS_ON` edges agree with SQL rows | ___ |
| Provenance | Export retains source SHA-256 | ___ |
| Security claims | No unsupported vulnerability edges | ___ |


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="3-4-test-repeatability-idempotency-and-historical-change"></a>

## 3.4. Test repeatability, idempotency and historical change

Re-run the **live-source loader without re-downloading**; verify that the record counts stay the same:

```bash
poetry run python src/load_live_pg.py
poetry run python src/load_live_pg.py
docker compose -f docker-compose.tutorial.yml exec -T postgres \
 psql -U knowledge -d knowledge_lab -c \
 'SELECT (SELECT COUNT(*) FROM live.snapshots) AS snapshots, (SELECT COUNT(*) FROM live.sbom_edges) AS edges;'
```

The tutorial loader currently clears and reloads the `live` schema **inside a disposable database**. That demonstrates reproducibility, **not** incremental idempotent processing: it does not preserve previous source snapshots. To compare *historical inventory changes*, re-run the separate fixture SQLite pipeline and its query in Section 1B.4.

**Design exercise for the upcoming project:** keep Bronze source objects immutable (URI + SHA-256); give every ingestion an ID and timestamp; deduplicate snapshots by content hash; implement source-specific upserts (`INSERT … ON CONFLICT` now, BigQuery `MERGE` later); maintain history with validity intervals; and ensure a second identical run cannot double-count or leave stale `AFFECTED_BY` edges.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="3-5-source-discovery-make-the-pipeline-extensible"></a>

## 3.5. Source discovery — make the pipeline extensible

**Source discovery** is not the same as ingestion. While processing a trusted advisory, we often encounter a reference (vendor bulletin, patch release, NVD record, exploit report) that could enrich the knowledge base. We should **register, qualify and prioritize** it before deciding to crawl or ingest it.

Our original `demo.py` registered a candidate Apache security advisory from OSV `references[]`. Reproduce that idea from the **real** local OSV JSON:

```bash
poetry run python - <<'PY'
import json
from urllib.parse import urlparse
x=json.load(open('data/raw/osv_log4shell.json'))
for ref in x.get('references',[])[:15]:
    url=ref.get('url','')
    p=urlparse(url)
    if p.scheme in ('https','http') and p.hostname:
        print(ref.get('type'),p.hostname,url)
PY
```

This **lists candidates only**; it does not automatically fetch arbitrary URLs from data (avoid SSRF, credentials leakage, unbounded crawling and restricted-license material). Create a registry with fields:

| Candidate field | Purpose |
|---|---|
| `url`, `discovered_in_cve`, `source_snapshot_sha` | Provenance: *where did we discover the lead?* |
| `publisher`, `source_kind`, `trust_tier` | Is it a primary vendor/security authority or a secondary summary? |
| `access_method`, `format`, `licence` | Can we legally/reliably ingest it? API, HTML, PDF, JSON? |
| `entity_keys`, `expected_freshness` | What join does it enable? How often should we revisit? |
| `status`, `reviewer`, `decision_reason` | `candidate → reviewed → approved/rejected → active` |

**Exercise:** identify two vendor-reference URLs in OSV. For each, specify the new *fact* it could contribute, the entity link (CVE? package? release?), what ingestion would cost, and whether it improves our narrow application-exposure question. A discovered URL is **not** an accepted source until qualified. This is central to building an independent knowledge product rather than simply accumulating files.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="3-6-demonstrate-bounded-pagination-and-operational-limits"></a>

## 3.6. Demonstrate bounded pagination and operational limits

The manifest already confirms GitHub supplied a `Link: rel="next"`. For a quick *manual* second-page experiment:

```bash
poetry run python - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('data/raw/live_manifest.json').read_text())
print(next(r.get('link_header') for r in m if r['name']=='github_advisories_page1'))
PY
```

Follow the `rel="next"` URL **only on the approved `api.github.com` host**, limit yourself to one extra page, record returned IDs and compare them to page one; keep its response and headers. A future Python paginator should parse `Link`, enforce page caps, respect GitHub rate limit headers and implement backoff/checkpointing. The OSV query API can use a different pagination contract (e.g. `next_page_token`); do not force a single pagination algorithm across sources.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="final-validation-sign-off-first-project-exploration-gate"></a>

### Final validation sign-off (first project *exploration* gate)

| Gate | Outcome on **my VM** | Evidence command/file | What's missing for a production claim? |
|---|---|---|---|
| Fixture dependency graph | ___ | Recursive SQL, unit tests | Real enterprise inventory coverage |
| Live raw retrieval | ___ | `live_manifest.json` and SHA test | Pagination, history, retries, scheduled replay |
| Real-source normalization | ___ | `live.*`, entity counts | More variants, full schema validation, aliases |
| Matching | ___ | Candidate SQL + golden tests | Complete Maven range semantics and unknown handling |
| Graph-ready export | ___ | `pg_graph_*.json` + referential assertions | Proven exposure edges and convergent external synchronization |
| Source discovery | ___ | Candidate registry entries | Qualification and lawful ingestion policy |

Record OS/Python/Poetry/PostgreSQL versions, date in UTC, repository commit, raw hashes, test output and failed assumptions. **Do not place credentials or proprietary SBOM contents in team logs.**

---

<a id="section-4-turn-the-exploratory-proof-into-the-bootcamp-delivery"></a>

# Section 4 — Turn the exploratory proof into the bootcamp delivery


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="4-1-planned-tools-mapped-to-our-actual-security-data"></a>

## 4.1. Planned tools mapped to our **actual** security data

| Tool / concept | What we will build with it | Concrete output and gate |
|---|---|---|
| **Python + Poetry** | Reproducible source adapters, CycloneDX parser, Maven matcher, graph exporter; lock versions | `pyproject.toml`, lockfile, tested package; no global-Python surprises |
| **Docker / Compose** | Local PostgreSQL and reproducible dev runners, eventually API/UI services | `docker compose up`, health checks, non-public DB ports |
| **GCS (Google Cloud Storage)** | **Bronze**: immutable raw OSV/GHSA/KEV/SBOM bytes and manifests | Object URI + SHA-256 + source headers; replayable captures |
| **BigQuery** | **Silver**: normalized advisories, identifiers, packages, inventory versions and dependencies | Tables keyed by source, entity and snapshot; partitioned incremental ingestion |
| **dbt** | Model lineage, canonical identifiers, SQL tests, **Gold** exposure and prioritization marts | Tested joins, deduplication, relationships, history and current-state views |
| **SQLite → PostgreSQL** | SQLite for fixture comprehension; PostgreSQL for real-source JSONB, joins and constraints | Section 1 `validation.sqlite`; Sections 2–3 `live.*`; not necessarily production warehouse |
| **Airflow** | Coordinate source refresh, raw persistence, normalization, matching, mart materialization and exports | DAG with retries, checkpoints, idempotent re-runs, failure alerts |
| **FastAPI** | Present read-only marts, freshness, explanation/evidence endpoints and graph-export contract | Stable JSON API with traceable evidence links |
| **Streamlit** | Demonstrate affected applications, dependency path, CVE, before/after exposure | Dashboard backed by Gold; explicit unknown/no-match states |
| **Neo4j + provided VPS KG-RAG service** | Future consumer of normalized nodes/edges and provenance; *provided integration*, not today's exercise | Sync contract, graph traversal, old-edge retirement and grounded retrieval |
| **pytest, dbt tests, SQL checks, CI** | Guard source structure, Maven semantics, DAG replay and knowledge correctness | Regression suite and written pass/fail gates |
| **Terraform (optional)** | Reproducible cloud resources, IAM and deployment if time allows | Idempotent infrastructure definition, least-privilege roles |


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="4-2-delivery-architecture-what-is-built-versus-consumed"></a>

### 4.2. Delivery architecture — what is built versus consumed

```text
                         PUBLIC / AUTHORIZED SOURCES
        OSV JSON    GitHub GHSA API    CISA KEV    CycloneDX SBOM
             \          |                |              /
              \         |                |             /
               v        v                v            v
            [Python source adapters: APIs, pagination, retries]
                        |
            [Source registry / candidate discovery]
                        |
               [SHA-256 + run manifest]
                        |
                        v
          ┌──────────── GCS BRONZE ────────────┐
          │ immutable raw JSON + manifests    │
          └─────────────────┬─────────────────┘
                            |
                  [Python parsing + QA]
                            |
                            v
          ┌───────── BIGQUERY SILVER ─────────┐
          │ sources / advisories / aliases    │
          │ packages / versions / SBOM nodes  │
          │ dependency edges / range events   │
          └─────────────────┬─────────────────┘
                            |
              [dbt joins + Maven range matcher]
              [dependency traversal + unknown policy]
                            |
                            v
          ┌────────── BIGQUERY GOLD ──────────┐
          │ current & historical exposures    │
          │ affected paths / prioritization   │
          │ source evidence / graph-ready N/E │
          └────────────┬───────────┬──────────┘
                       |           |
                       v           v
                [Streamlit UI]  [FastAPI / graph export]
                                   |
                     [Provided VPS API + Neo4j / KG-RAG]
                     [future contract and sync validation]

        AIRFLOW: schedules and monitors the end-to-end DAG
        PYTEST / DBT TESTS / CI: validation gates along the path
        DOCKER + POETRY: reproducible execution and dev environment
        SOURCE REGISTRY: discovery → qualification → approved ingestion
```

**Where knowledge is created:** primarily between Silver and Gold when we establish the *same package*, evaluate its *affected version*, traverse its *application dependency path* and attach evidence. **Where idempotency is introduced:** first at Bronze content hashes, then Silver stable keys/upserts, then Gold incremental recomputation and graph synchronization. **Where validation runs:** at every transition, not only at the end.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="4-3-sequential-implementation-backlog-half-day-delivery-gates"></a>

### 4.3. Sequential implementation backlog (half-day delivery gates)

| # | Dependency / order | Deliverable | Definition of done |
|---|---|---|---|
| 1 | Team shares tutorial understanding | Agree entities, primary CVE, controlled SBOM, API boundary | Everyone can explain the application → package → CVE path |
| 2 | Source selection | Source registry v0 + access adapters | Five live downloads, hashes, bounded pagination notes |
| 3 | Raw persistence | GCS Bronze object convention + manifest | Repeated fetch does not corrupt historical snapshots |
| 4 | Normalization | BigQuery Silver schemas and Python loaders | OSV/GHSA/KEV/SBOM identities, referential checks |
| 5 | Matching | Maven-aware version matcher with golden cases | Correct affected/not/unknown for verified multi-event cases |
| 6 | Knowledge generation | Gold marts, dependency paths, evidence fields | Query answers *which app, why, since when, source?* |
| 7 | Orchestration | Airflow DAG including retries/reprocessing | Repeatable incremental run and visible failures |
| 8 | Delivery | Streamlit + read API + graph export | Before/after vulnerability exposure shown, exports validated |
| 9 | Later integration | VPS contract, Neo4j reconciliation | Stable IDs, provenance path, update + stale-edge retirement |

**Critical path:** source contracts → canonical package keys → Maven matcher → Gold exposure. A pretty dashboard cannot compensate for incorrect version matching.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="4-4-parallel-work-plan-five-half-days-from-monday-afternoon-to-wednesday-afternoon"></a>

## 4.4. Parallel work plan — **five half-days** from Monday afternoon to Wednesday afternoon

**Monday AM (protected):** everyone independently completes Sections 1–3; compare interpretation and choose the CVE/SBOM test matrix. **Thursday AM:** reserved backup/hardening. **Thursday PM:** intentionally free for career-related meetings. Designate one integrator and agree on code contracts by Monday lunch.

| Time | Stream A — acquisition + orchestration | Stream B — normalization + matching | Stream C — product + serving / integration | Whole-team checkpoint |
|---|---|---|---|---|
| **Mon PM** | Define registry, APIs, manifests, GCS path convention; produce first immutable raw capture | Design Silver schemas, keys, OSV event representation, SBOM relationships; implement seed parsers | Design Gold output contract, exposure/path schema, Streamlit wireframe, graph JSON contract | Shared schema and precise scope frozen by end of PM |
| **Tue AM** | Implement safe paginated/retry-able ingestion and GCS upload; test repeated downloads | Load BigQuery Silver, dbt source tests; curate Maven golden cases | Build minimal read API + dashboard against fixture Gold shape | Real raw → Silver records independently inspectable |
| **Tue PM** | Add Airflow DAG skeleton, retries/checkpoints and manifest assertions | Implement Maven matcher with affected/not/unknown; dependency traversal; first Gold exposure | Connect dashboard to Gold; draft evidence and changed-state views | One complete controlled exposure traced end-to-end |
| **Wed AM** | Schedule incremental runs, backfills, idempotency checks, monitor failures | Add alias resolution, historical exposure model, dbt tests, source provenance | Export stable graph-ready nodes/edges, enforce relationship/evidence checks; API if ready | Second run produces correct before/after transition |
| **Wed PM** | Finalize operational evidence and runbook | Fix golden-case failures, validate no silent false negatives | Demo narrative + dashboards + future VPS boundary documentation | Team rehearses end-to-end demonstration and freezes demo inputs |

If fewer people are available, collapse Stream C into Streams A/B after Silver has a stable contract. **Avoid three people editing the same Python module or dbt model**; use feature branches and well-defined interface files (`sources.yml`, normalized columns, Gold mart schema, graph export schema).


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="4-5-suggested-ownership-and-branch-interface-agreements"></a>

### 4.5. Suggested ownership and branch/interface agreements

- **Acquisition owner:** `src/ingest/`, Bronze object naming, source registry and raw manifest schema. Contract: immutable raw object URI + SHA-256 + source status.
- **Transform owner:** `src/normalize/`, `src/matching/`, `models/silver/`, `models/gold/`, golden version tests. Contract: normalized package keys, exposure status and evidence references.
- **Product owner:** Streamlit, FastAPI read-only endpoints, graph export node/edge schema, demo. Contract: Gold marts and stable evidence-linked IDs.
- **Integrator (rotating or one lead):** reviews schema changes, merges work after tests, maintains single end-to-end demo run, tracks blockers.

**Daily merge rule:** integrate and run the mini E2E test at each half-day checkpoint. Do not postpone integration until Wednesday night.


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="4-6-minimum-wednesday-acceptance-and-what-remains-intentionally-outside"></a>

### 4.6. Minimum Wednesday acceptance (and what remains intentionally outside)

A strong Wednesday demonstration should show: (1) real source captures with manifests; (2) normalized canonical entities in Silver; (3) tested matching for at least one CVE and two installed versions; (4) a traversable dependency path; (5) before/after Gold exposure; (6) evidence hashes and freshness; (7) a Streamlit presentation; and (8) graph-ready exports. If the matcher is incomplete, label the unsupported cases **unknown** and show the tests rather than exaggerating coverage.

**Out of scope for this tutorial:** real VPS/Neo4j ingestion, security certification, fully scalable bulk OSV acquisition, full Maven ecosystem coverage, and deployment of a production-grade KG-RAG agent. Those have separate contracts and acceptance steps; the tutorial makes their required data products and interface assumptions visible.

---

<a id="quick-reference-commands-to-rerun-with-the-team"></a>

# Quick reference — commands to rerun with the team

```bash
# Section 1 — curated, offline, SQLite (no Docker or PostgreSQL)
poetry env use python3.12
poetry install
poetry run python src/validate.py
poetry run python -m unittest discover -s tests -v
sqlite3 -header -column data/outputs/validation.sqlite < sql/validation_queries.sql
poetry run python -m json.tool data/outputs/graph_edges_run1.json

# Section 2 — real downloaded data in PostgreSQL
export DATABASE_URL='postgresql://knowledge:tutorial_local_only@127.0.0.1:5433/knowledge_lab'
docker compose -f docker-compose.tutorial.yml up -d
docker compose -f docker-compose.tutorial.yml exec -T postgres \
  psql -v ON_ERROR_STOP=1 -U knowledge -d knowledge_lab < sql/pg_live.sql
poetry run python src/fetch_live.py
poetry run python src/load_live_pg.py
docker compose -f docker-compose.tutorial.yml exec -T postgres \
  psql -U knowledge -d knowledge_lab < sql/pg_live_queries.sql

# Section 3 — tests, graph-ready export, no VPS needed
poetry run pytest -q
poetry run python src/export_pg_graph.py
```


<p class="back-top"><a href="#top">↑ Back to top</a></p>

<a id="references-and-continuity"></a>

## References and continuity

- Earlier team artifacts: `Protocol_for_removing_the_remaining_blockers.md`; `knowledge_demo/demo.py`; `Knowledge_Pipeline_Demo_Fundamentals.md`; previous `VALIDATION_PROTOCOL.md`, `EXECUTION_RESULTS.md`, `TEAM_RUN_LOG_TEMPLATE.md` (reinterpreted and folded into this tutorial).
- Source documentation: [OSV query API](https://google.github.io/osv.dev/post-v1-query/), [GitHub global advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories), [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [CycloneDX example SBOMs](https://github.com/CycloneDX/bom-examples), [PostgreSQL recursive queries](https://www.postgresql.org/docs/14/queries-with.html), [Poetry docs](https://python-poetry.org/docs/).
- Historical observation: 22 Nov 2026 Mac manifest showed all five HTTP 200 responses after fixing python.org certificate trust. Those downloaded raw files were **not** included in the original ZIP; teammates must retrieve their own, or use authorized versioned snapshots.

<p class="back-top"><a href="#top">↑ Back to top</a></p>

---

<a id="checkpoints-answers"></a>

# Checkpoints Answers

> **Read after the exercises.** These are reference answers for the teaching fixtures and expected interpretations, **not** a substitute for the values actually observed on your VM. For live sources, record your own counts, hashes, timestamps and URL metadata; they can change.

## Answer to Checkpoint 1A — Data, knowledge and evidence

1. **Data:** An **OSV (Open Source Vulnerabilities)** advisory describes a vulnerability, affected ecosystem/package and version ranges. An **SBOM (Software Bill of Materials)** describes what packages/versions an application uses and how its components depend on one another. Neither alone identifies this application's exposure.
2. **Knowledge:** Match the same **ecosystem + canonical package identity**, evaluate the **installed version against affected ranges**, and traverse `DEPENDS_ON` edges to establish that the package belongs to the application. The **derived exposure** is new knowledge. A transitive hop matters because an application can inherit a vulnerable package through another dependency.
3. **Evidence:** Retain the raw advisory/SBOM bytes, provenance URL, retrieval UTC time, SHA-256 content hashes, package identifiers, version decision, traversal path, evaluation rules and run ID. The hashes identify input snapshots; an audit should also record the code version and any ambiguities.

[↑ Back to top](#top)

## Answer to Checkpoint 1B — Fixture results and SQLite

| Question | Expected observation from the curated fixture | Where to check |
|---|---|---|
| Run 1 | `Billing` / `log4j-core` / `2.14.1` / `affected` (only for the illustrative range) | `SELECT run_id,app,version,status FROM exposures ORDER BY run_id,app;` |
| Dependency depth | `Billing → billing-helper → log4j-core`, two dependency edges/hops | `sql/validation_queries.sql` recursive CTE |
| Run 2 | `Billing` upgraded to `2.17.1`; `not_affected` for the chosen CVE interval | Same `exposures` query |
| Graph-ready output | Run 1: **4 nodes and 3 edges**; run 2: **4 nodes and 2 edges** (lost the derived `AFFECTED_BY` edge) | `data/outputs/graph_*_run*.json` |
| Integrity/rerun | `PRAGMA integrity_check` is `ok`; `PRAGMA foreign_key_check` yields zero rows; fixture outputs are logically repeatable | SQLite CLI commands |

**What not to infer:** A rebuilt SQLite file demonstrates reproducible batch computation, **not** idempotent incremental database writes. A comparison against the simplified Log4Shell interval is **not** complete Maven version evaluation.

[↑ Back to top](#top)

## Answer to Checkpoint 2A — Live manifest and interpretation

The successful **22 November 2026 macOS run** observed five HTTP 200 responses: OSV Log4Shell 112,802 bytes; GitHub Log4Shell 12,791; GitHub advisories first page 52,555; CISA KEV 1,871,127; and CycloneDX dependency example 1,542. These are **historical observations**, not guaranteed values for your later run. The total downloaded payload was **2,050,817 bytes (~1.96 MiB)**.

| Source | Primary join key | Change/pagination behavior to investigate |
|---|---|---|
| OSV | CVE identifier and `affected[].package` (`Maven`, `group:artifact`) | `modified` and content hash; query/bulk mechanisms differ |
| GitHub advisory | `ghsa_id`, `cve_id`, package vulnerabilities | `updated_at`, `ETag`; possible authentication/rate limits |
| GitHub listing | `ghsa_id` per item | HTTP `Link` with `rel="next"` (observed cursor), cap pages and follow supplied link |
| CISA KEV | `cveID` | Refresh the full catalogue, compare version/hash and entries |
| CycloneDX | SBOM-local `bom-ref`, ecosystem-aware `purl` | Snapshot/commit hash; `dependsOn` references; not necessarily Log4j |

**SSL troubleshooting:** The previous Mac used python.org Python 3.14 without a trusted certificate bundle; its `Install Certificates.command` fixed HTTPS verification. The VM's Python 3.12/Poetry environment may differ. Never disable TLS verification.

[↑ Back to top](#top)

## Answer to Checkpoint 2B — PostgreSQL results and zero matches

- With all five successful files, `live.snapshots` should contain **five source snapshot records** after one fresh loader run; confirm with SQL.
- `live.osv_affected` can contain **more than one** affected package/range. Preserve the full `ranges_json` structure rather than discarding entries after the first event.
- `live.sbom_components` and `live.sbom_edges` express the public CycloneDX **CBOM** dependency example; check `bom-ref` uniqueness and that every edge endpoint exists. Counts depend on the actual downloaded file.
- Joining GHSA ↔ CVE and KEV ↔ CVE gives **cross-source corroboration/metadata**, not a new vulnerable application on its own.
- A **zero-row** join between the public CBOM and the Log4Shell OSV package is expected to be possible: we selected the CBOM for dependency-structure teaching, **not** because it contains Maven Log4j. Zero matches is not evidence that an enterprise is safe.
- A **synthetic Billing** test inventory can join to a **real** OSV package; label the inventory synthetic and the advisory real. Package identity alone is not exposure: ranges must still be evaluated.
- **Full Maven version evaluator** remains **pending** until independently tested against real range events/qualifiers. Output `unknown` rather than guessing.

[↑ Back to top](#top)

## Answer to Checkpoint 3.3 — Graph-ready export

| Check | How to establish the answer | Expected principle |
|---|---|---|
| Endpoints | Compare every `source`/`target` in edge JSON against node IDs | No dangling edge IDs |
| Dependencies | Compare exported `DEPENDS_ON` edges against `live.sbom_edges` | Same directed relations |
| Provenance | Verify source snapshot SHA-256 appears in exported data | Auditable input lineage |
| Security claims | Search for `AFFECTED_BY` edges in the real-data export | None until package, path and complete supported version matcher establish a justified exposure |

A graph-ready JSON export is not equivalent to a populated Neo4j database. Also, an eventual graph synchronizer must remove or time-scope stale `AFFECTED_BY` edges when inventories change; upserts alone do **not** remove old claims.

[↑ Back to top](#top)

## Final sign-off — How to interpret the exploratory gate

**Pass** only a claim directly supported by your command output and source artifacts. Mark partial when a fixture works but live API/PG verification is missing. Document remaining blockers (comprehensive Maven version matching, industrial-grade incremental history, real VPS/Neo4j synchronization), and preserve the exact command, timestamp, code revision and evidence path in the embedded tables.

[↑ Back to top](#top)

