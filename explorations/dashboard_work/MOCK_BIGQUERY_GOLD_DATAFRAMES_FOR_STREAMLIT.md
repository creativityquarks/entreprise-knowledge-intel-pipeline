# Mock BigQuery Gold DataFrames for Streamlit

> **Enterprise Knowledge Intelligence Pipeline — Dashboard development**  
> Four pandas DataFrames generated in memory by `mock_gold_data.py`. No BigQuery connection or file exports are required.

I created a **single Python script** that generates four pandas DataFrames simulating our BigQuery Gold output, ready for Streamlit.

**Python script:** [`mock_gold_data.py`](../mock/mock_gold_data.py)

## Generated DataFrames

| DataFrame | Rows | Purpose |
|---|---:|---|
| `mart_application_overview` | 5 | Application list, severity flags and vulnerability counts |
| `mart_application_findings` | 5 | Detailed vulnerabilities, components, dates, URLs and provenance |
| `graph_nodes` | 20 | Applications, components and vulnerabilities |
| `graph_edges` | 15 | Relationships for the future knowledge graph |

The names match the four Gold views in the Airflow-first MVP. The mock adds proposed dashboard fields, including severity labels, CVSS scores, publication dates and dependency paths.

## Example application overview

| Application | Severity | Findings |
|---|---|---:|
| Billing | 🔴 **Critical** | 2 |
| Analytics | 🔴 **Critical** | 1 |
| Customer Portal | 🔴 **Critical** | 1 |
| Inventory API | 🟠 **High** | 1 |
| Reporting | ⚪ **No known matches** | 0 |

**All data is synthetic** for dashboard development, not verified findings about real applications. A “no known matches” flag must never be interpreted as proof of security.

## How to use it

Install pandas if needed:

```bash
poetry add pandas
```

Place `mock_gold_data.py` where your Streamlit application can import it, or add its directory to the Python import path. Then:

```python
from mock_gold_data import build_mock_gold

gold = build_mock_gold()

overview = gold["mart_application_overview"]
findings = gold["mart_application_findings"]
nodes = gold["graph_nodes"]
edges = gold["graph_edges"]
```

Display the overview and an application-specific detail table:

```python
import streamlit as st

st.title("Application Vulnerability Dashboard")
st.dataframe(overview, hide_index=True)

selected = st.selectbox(
    "Select application",
    overview["application_name"].tolist()
)

st.dataframe(
    findings[findings["application_name"] == selected],
    hide_index=True
)
```

You can inspect the generated data directly from the CLI:

```bash
poetry run python mock_gold_data.py
```

## Gold schema: columns available to the dashboard

| DataFrame | Important columns |
|---|---|
| `mart_application_overview` | `application_id`, `application_name`, `finding_count`, `affected_components`, `risk_flag`, `severity_label`, `max_cvss_score`, `inventory_snapshot_sha256` |
| `mart_application_findings` | `application_id`, `application_name`, `component_name`, `component_version`, `package_name`, `vulnerability_id`, `finding_status`, `severity_label`, `cvss_score`, `published_at`, `dependency_path`, `vulnerability_summary`, `advisory_url`, `sbom_sha256`, `osv_query_sha256`, `sbom_gcs_uri` |
| `graph_nodes` | `node_id`, `node_type`, `label`, `source_sha256` |
| `graph_edges` | `source_id`, `relation`, `target_id`, `sbom_sha256`, `osv_query_sha256` |

The graph tables represent `HAS_INVENTORY`, `DEPENDS_ON` and `AFFECTED_BY` relationships. The script checks that every edge endpoint exists among its nodes and that the overview counts reconcile with the findings table.

**No CSV, Parquet or database files are generated.** The DataFrames exist only in memory, allowing us to develop the dashboard independently of Airflow and BigQuery.

When the real Gold views become available, replace `build_mock_gold()` with a BigQuery-loading function that returns the same four named DataFrames and preserves the column contract.
