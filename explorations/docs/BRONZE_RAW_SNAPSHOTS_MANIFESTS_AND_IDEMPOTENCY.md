# Bronze Raw Snapshots, Manifests & Idempotency

**Enterprise Knowledge Intelligence Pipeline**

Yes, exactly. What you downloaded using `fetch_live.py` is the beginning of our **Bronze layer**.

The important architectural distinction is between **retrieving data, deciding whether to store it, and processing it**.

## 1. Do we call the downloaded data a raw snapshot?

**Yes.** Each downloaded JSON file represents a raw snapshot of a source at a particular moment.

For example:

```text
data/raw/
├── osv_log4shell.json
├── github_log4shell.json
├── github_advisories_page1.json
├── cisa_kev.json
├── cyclonedx_dependencies.json
└── live_manifest.json
```

In your successful execution, the OSV record was downloaded on November 22, 2026.

A snapshot has three important characteristics:

- **Raw:** the original response bytes are preserved, without normalization or transformation.
- **Time-specific:** we know when the data was retrieved.
- **Traceable:** we know its origin, HTTP metadata and SHA-256 hash.

One limitation of our current demonstration: `fetch_live.py` saves files under fixed names. Running it again can overwrite the previous files.

In the production pipeline, we should instead make stored snapshots **immutable**.

## 2. Is that everything Bronze should contain?

Not quite. Bronze should contain the raw source data **and the information needed to manage its provenance and processing**.

I would distinguish three elements:

| Element | Content | Purpose |
|---|---|---|
| **Raw snapshots** | Original OSV, GitHub, KEV and SBOM JSON files | Preserve source evidence |
| **Ingestion manifest** | URL, retrieval timestamp, SHA-256, HTTP status, ETag, object path | Track what was retrieved and stored |
| **Ingestion state** | Last successful ingestion, pagination cursor, previous hashes, errors | Enable incremental ingestion and recovery |

The ingestion state can live in PostgreSQL or another metadata store rather than in the raw-data directory itself.

A possible GCS structure:

```text
gs://knowledge-pipeline-bronze/
├── raw/
│   ├── osv/
│   │   └── CVE-2021-44228/
│   │       ├── sha256-aaa....json
│   │       └── sha256-bbb....json
│   ├── github/
│   ├── cisa-kev/
│   └── cyclonedx/
│
└── manifests/
    ├── run_001.json
    ├── run_002.json
    └── run_003.json
```

A useful principle is that **every ingestion run can have its own manifest, without necessarily creating new raw snapshots**.

For example, if today's OSV JSON is identical to yesterday's, the new manifest can reference the existing stored object.

## 3. When do we calculate the hash and prevent duplicates?

**During ingestion, immediately after downloading the response and before persisting it as a new raw object.**

### Ingestion and deduplication flow

```text
1. Fetch source
   HTTP GET → original response bytes
                │
                ▼
2. Compute SHA-256
   Hash the exact downloaded bytes
                │
                ▼
3. Check whether content already exists
         ┌──────┴──────┐
         ▼             ▼
     Same hash       New hash
     Reuse existing  Store a new immutable snapshot
     snapshot        and register it in the manifest
         └──────┬──────┘
                ▼
4. Trigger Silver processing when needed
   Parse · Normalize · Validate · Resolve identifiers
```

### Python example

This illustrates the logic we should introduce into the ingestion script:

```python
import hashlib
from pathlib import Path
from urllib.request import urlopen

url = "https://example.org/advisory.json"

with urlopen(url, timeout=30) as response:
    raw_bytes = response.read()

digest = hashlib.sha256(raw_bytes).hexdigest()

bronze = Path("data/bronze/osv")
bronze.mkdir(parents=True, exist_ok=True)

snapshot = bronze / f"{digest}.json"

if snapshot.exists():
    print("Unchanged: reusing existing snapshot")
else:
    with snapshot.open("xb") as file:
        file.write(raw_bytes)

    print("New snapshot stored:", snapshot)
```

For production GCS ingestion, we'd use a conditional object creation operation to avoid concurrency races, rather than relying only on a local `exists()` check.

Also, for separate sources, object identity should include the source identifier or namespace. Two sources may return identical bytes but still represent different provenance.

## 4. A subtle but important distinction: three kinds of idempotency

In our project, deduplication and idempotency will operate at different levels.

| Level | What we prevent | Example |
|---|---|---|
| **Bronze — content** | Storing identical raw bytes repeatedly | Same OSV JSON downloaded twice |
| **Silver — entities** | Creating duplicate normalized records | The same CVE appearing in OSV and GitHub |
| **Gold — knowledge** | Recreating identical conclusions or relationships | Billing → AFFECTED_BY → CVE-2021-44228 |

These are different problems.

For instance, OSV and GitHub may both refer to `CVE-2021-44228`. We should preserve **both original source records** in Bronze, because they are independent evidence.

In Silver, we may create a canonical vulnerability entity with links to both source records.

In Gold, we should avoid creating duplicate exposure relationships for the same application, component, vulnerability and observation state.

We must also preserve history: a changed exposure status should create a meaningful new state, not erase the previous one.

## 5. Where does this fit into our intended architecture?

| Stage | Technology | Our specific responsibility |
|---|---|---|
| Ingestion | Python + Airflow | Download, hash, detect changes and schedule processing |
| Bronze | GCS | Store immutable source snapshots and manifests |
| Metadata/state | PostgreSQL or BigQuery | Track successful ingestions, snapshot hashes, cursors and failures |
| Silver | BigQuery + dbt/Python | Normalize packages, versions, CVEs, aliases and dependencies |
| Gold | BigQuery + dbt/Python | Calculate exposure states, history and graph-ready relationships |
| Graph integration | API + Neo4j | Synchronize nodes and edges with their provenance |

For our bootcamp, there is an important practical distinction: the `fetch_live.py` script already calculates SHA-256 and records it in `live_manifest.json`, but **it does not yet use the hash to avoid duplicate raw-file storage or preserve historical snapshots**.

That is a feature we still need to implement.

### My recommendation

Implement content-addressed, immutable storage as soon as we build the real Bronze ingestor, rather than waiting until the Gold layer.

The resulting principle is:

**Fetch every time required for freshness; store new content only when necessary; process changed content only when necessary; always retain evidence of the ingestion run.**

One additional optimization will come later: using HTTP conditional requests (`If-None-Match` with ETag or `If-Modified-Since`) to avoid downloading unchanged content when the source supports it. Those responses and their limitations should also be recorded in our ingestion metadata.
