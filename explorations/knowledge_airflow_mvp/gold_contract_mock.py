"""Gold Layer Data Contract (Synthetic DataFrames for Streamlit & Pipeline Target).

Run standalone to inspect tables:
    python mock_gold_data.py

Use in Streamlit (app.py):
    from mock_gold_data import build_mock_gold
    gold = build_mock_gold()
"""

import pandas as pd

# Single shared hash representing one OSV /v1/querybatch snapshot (raw/osv_batch/<sha>.json)
BATCH_OSV_QUERY_SHA = "99887766554433221100osv_batch_snapshot_sha256"
SNAPSHOT_TS = pd.Timestamp("2026-11-20T08:00:00Z")


def build_mock_gold() -> dict[str, pd.DataFrame]:
    """Return four mutually consistent Gold DataFrames honoring the MVP data contract."""
    apps = [
        ("billing-prod", "Billing"),
        ("analytics-prod", "Analytics"),
        ("customer-portal", "Customer Portal"),
        ("inventory-api", "Inventory API"),
        ("reporting", "Reporting"),  # Intentionally 0 findings to test NO_MATCH_IN_QUERIED_OSV
    ]
    app_names = dict(apps)
    app_sha = {app_id: f"synthetic-sbom-sha256-{i:02d}" for i, (app_id, _) in enumerate(apps, 1)}

    # Intermediate (transitive) components so graph_edges models real multi-hop paths
    # Format: (app_id, bom_ref, component_name, version, parent_bom_ref)
    intermediate_components = [
        ("billing-prod", "billing-helper", "billing-helper", "1.0.0", "root"),
    ]

    # Vulnerability findings
    # Format: (app_id, bom_ref, parent_bom_ref, component, package, version, vuln_id,
    #          v2_cvss, v2_published, v2_summary, v2_path)
    cases = [
        (
            "billing-prod", "log4j", "billing-helper", "log4j-core",
            "org.apache.logging.log4j:log4j-core", "2.14.1", "GHSA-jfh8-c2jp-5v3q",
            10.0, "2021-12-10", "Remote code execution via JNDI lookup (Log4Shell)",
            "Billing > billing-helper > log4j-core",
        ),
        (
            "billing-prod", "jackson", "root", "jackson-databind",
            "com.fasterxml.jackson.core:jackson-databind", "2.9.8", "CVE-2019-12384",
            8.1, "2019-06-21", "Polymorphic deserialization issue",
            "Billing > jackson-databind",
        ),
        (
            "analytics-prod", "spring", "root", "spring-beans",
            "org.springframework:spring-beans", "5.3.17", "CVE-2022-22965",
            9.8, "2022-03-31", "Spring Framework vulnerability under specific conditions",
            "Analytics > spring-beans",
        ),
        (
            "customer-portal", "commons", "root", "commons-text",
            "org.apache.commons:commons-text", "1.9", "CVE-2022-42889",
            9.8, "2022-10-13", "Text interpolation may enable code execution",
            "Customer Portal > commons-text",
        ),
        (
            "inventory-api", "snakeyaml", "root", "snakeyaml",
            "org.yaml:snakeyaml", "1.30", "CVE-2022-1471",
            8.3, "2022-12-01", "Unsafe deserialization under certain conditions",
            "Inventory API > snakeyaml",
        ),
    ]

    # ------------------------------------------------------------------
    # 1. Gold Table: mart_application_findings (Drill-down + Evidence)
    # ------------------------------------------------------------------
    details = []
    for (
        app_id, ref, parent_ref, component, package, version, vuln_id,
        v2_cvss, v2_published, v2_summary, v2_path,
    ) in cases:
        sha = app_sha[app_id]
        details.append({
            # --- Baseline MVP Contract Columns ---
            "application_id": app_id,
            "application_name": app_names[app_id],
            "bom_ref": ref,
            "component_name": component,
            "package_name": package,
            "component_version": version,
            "vulnerability_id": vuln_id,
            "finding_status": "KNOWN_VULNERABILITY",
            "severity_label": "UNRATED",  # MVP rule: UNRATED until CVSS scoring is validated
            "advisory_url": f"https://osv.dev/vulnerability/{vuln_id}",
            "sbom_sha256": sha,
            "osv_query_sha256": BATCH_OSV_QUERY_SHA,
            "sbom_gcs_uri": f"gs://example-bronze/raw/sbom_{app_id}/{sha}.json",
            "inventory_first_seen": SNAPSHOT_TS,
            # --- Iteration 2 Proposed Extensions (optional in UI) ---
            "v2_cvss_score": v2_cvss,
            "v2_published_at": pd.Timestamp(v2_published, tz="UTC"),
            "v2_dependency_path": v2_path,
            "v2_vulnerability_summary": v2_summary,
        })
    mart_application_findings = pd.DataFrame(details)

    # ------------------------------------------------------------------
    # 2. Gold Table: mart_application_overview (1 row per application)
    # ------------------------------------------------------------------
    overview_rows = []
    for app_id, name in apps:
        sub = mart_application_findings[mart_application_findings["application_id"] == app_id]
        has_findings = len(sub) > 0
        overview_rows.append({
            "application_id": app_id,
            "application_name": name,
            "finding_count": int(len(sub)),
            "affected_components": int(sub["bom_ref"].nunique()),
            "risk_flag": "KNOWN_VULNERABILITY" if has_findings else "NO_MATCH_IN_QUERIED_OSV",
            "severity_label": "UNRATED" if has_findings else "N/A",
            "inventory_snapshot_sha256": app_sha[app_id],
        })
    mart_application_overview = pd.DataFrame(overview_rows)

    # ------------------------------------------------------------------
    # 3 & 4. Gold Tables: graph_nodes & graph_edges
    # ------------------------------------------------------------------
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}

    def add_node(node_id: str, node_type: str, label: str, sha: str | None = None) -> None:
        nodes[node_id] = {
            "node_id": node_id,
            "node_type": node_type,
            "label": label,
            "source_sha256": sha,
        }

    def add_edge(
        src: str, rel: str, dst: str,
        sbom_sha: str | None = None, osv_sha: str | None = None,
    ) -> None:
        edges[(src, rel, dst)] = {
            "source_id": src,
            "relation": rel,
            "target_id": dst,
            "sbom_sha256": sbom_sha,
            "osv_query_sha256": osv_sha,
        }

    # Application & root inventory nodes
    for app_id, name in apps:
        sha = app_sha[app_id]
        root_node = f"component:{sha}:root"
        add_node(f"app:{app_id}", "Application", name)
        add_node(root_node, "ComponentVersion", name, sha)
        add_edge(f"app:{app_id}", "HAS_INVENTORY", root_node, sbom_sha=sha)

    # Intermediate transitive nodes (e.g., billing-helper)
    for app_id, ref, comp_name, version, parent_ref in intermediate_components:
        sha = app_sha[app_id]
        cmp_node = f"component:{sha}:{ref}"
        parent_node = f"component:{sha}:{parent_ref}"
        add_node(cmp_node, "ComponentVersion", f"{comp_name}@{version}", sha)
        add_edge(parent_node, "DEPENDS_ON", cmp_node, sbom_sha=sha)

    # Vulnerable component nodes, dependency edges, and AFFECTED_BY edges
    for (
        app_id, ref, parent_ref, component, _, version, vuln_id, *_
    ) in cases:
        sha = app_sha[app_id]
        cmp_node = f"component:{sha}:{ref}"
        parent_node = f"component:{sha}:{parent_ref}"
        vuln_node = f"vuln:{vuln_id}"

        add_node(cmp_node, "ComponentVersion", f"{component}@{version}", sha)
        add_node(vuln_node, "Vulnerability", vuln_id)
        add_edge(parent_node, "DEPENDS_ON", cmp_node, sbom_sha=sha)
        add_edge(
            cmp_node, "AFFECTED_BY", vuln_node,
            sbom_sha=sha, osv_sha=BATCH_OSV_QUERY_SHA,
        )

    graph_nodes = pd.DataFrame(nodes.values())
    graph_edges = pd.DataFrame(edges.values())

    # ------------------------------------------------------------------
    # Data Contract Assertions (Your real Silver->Gold code must pass these)
    # ------------------------------------------------------------------
    valid_flags = {"KNOWN_VULNERABILITY", "NO_MATCH_IN_QUERIED_OSV"}
    assert set(mart_application_overview["risk_flag"]).issubset(valid_flags), (
        "Invalid risk_flag; never label unmatched apps as 'secure'."
    )
    assert mart_application_overview["finding_count"].sum() == len(mart_application_findings), (
        "Overview finding counts must equal total rows in mart_application_findings."
    )
    assert set(graph_edges["source_id"]).union(graph_edges["target_id"]).issubset(
        set(graph_nodes["node_id"])
    ), "Orphan graph edge detected: every edge endpoint must exist in graph_nodes."
    affected_edges = graph_edges[graph_edges["relation"] == "AFFECTED_BY"]
    assert affected_edges["sbom_sha256"].notna().all() and affected_edges["osv_query_sha256"].notna().all(), (
        "Every AFFECTED_BY edge must carry both sbom_sha256 and osv_query_sha256."
    )

    return {
        "mart_application_overview": mart_application_overview,
        "mart_application_findings": mart_application_findings,
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
    }


if __name__ == "__main__":
    for table_name, df in build_mock_gold().items():
        print(f"\n=== {table_name} ({len(df)} rows) ===")
        print(df.to_string(index=False, max_colwidth=34))