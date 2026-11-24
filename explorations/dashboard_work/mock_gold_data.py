"""Synthetic BigQuery Gold DataFrames for Streamlit prototyping.

Run: python mock_gold_data.py
Use: from mock_gold_data import build_mock_gold
No BigQuery connection or disk exports.
"""
import pandas as pd


def build_mock_gold():
    """Return four mutually consistent, synthetic Gold dataframes."""
    apps = [
        ("billing-prod", "Billing", "Critical"),
        ("analytics-prod", "Analytics", "High"),
        ("customer-portal", "Customer Portal", "Medium"),
        ("inventory-api", "Inventory API", "Low"),
        ("reporting", "Reporting", "None"),
    ]
    # app, bom_ref, component, package, installed, CVE, severity, score,
    # publication, disclosure snippet, dependency path
    cases = [
        ("billing-prod", "log4j", "log4j-core", "org.apache.logging.log4j:log4j-core", "2.14.1", "CVE-2021-44228", "Critical", 10.0, "2021-12-10", "Remote code execution in certain configurations", "Billing > billing-helper > log4j-core"),
        ("billing-prod", "jackson", "jackson-databind", "com.fasterxml.jackson.core:jackson-databind", "2.9.8", "CVE-2019-12384", "High", 8.1, "2019-06-21", "Polymorphic deserialization issue", "Billing > jackson-databind"),
        ("analytics-prod", "spring", "spring-beans", "org.springframework:spring-beans", "5.3.17", "CVE-2022-22965", "Critical", 9.8, "2022-03-31", "Spring Framework vulnerability under specific conditions", "Analytics > spring-beans"),
        ("customer-portal", "commons", "commons-text", "org.apache.commons:commons-text", "1.9", "CVE-2022-42889", "Critical", 9.8, "2022-10-13", "Text interpolation may enable code execution", "Customer Portal > commons-text"),
        ("inventory-api", "snakeyaml", "snakeyaml", "org.yaml:snakeyaml", "1.30", "CVE-2022-1471", "High", 8.3, "2022-12-01", "Unsafe deserialization under certain conditions", "Inventory API > snakeyaml"),
    ]
    app_names = {app_id: name for app_id, name, _ in apps}
    app_sha = {app_id: f"synthetic-sbom-{i:02d}" for i, (app_id, _, _) in enumerate(apps, 1)}
    query_sha = {cve: f"synthetic-osv-{i:02d}" for i, cve in enumerate(sorted({r[5] for r in cases}), 1)}
    details = []
    for app_id, ref, component, package, version, cve, severity, score, published, summary, path in cases:
        details.append({
            "application_id": app_id, "application_name": app_names[app_id],
            "bom_ref": ref, "component_name": component,
            "package_name": package, "component_version": version,
            "vulnerability_id": cve, "finding_status": "KNOWN_VULNERABILITY",
            "severity_label": severity,
            "advisory_url": f"https://osv.dev/vulnerability/{cve}",
            "sbom_sha256": app_sha[app_id], "osv_query_sha256": query_sha[cve],
            "sbom_gcs_uri": f"gs://example-bronze/raw/sbom/{app_id}/{app_sha[app_id]}.json",
            "inventory_first_seen": pd.Timestamp("2026-11-20", tz="UTC"),
            # Proposed extensions for the next Gold mart version:
            "cvss_score": score,
            "published_at": pd.Timestamp(published, tz="UTC"),
            "dependency_path": path,
            "vulnerability_summary": summary,
            "match_confidence": "SYNTHETIC_DEMO",
        })
    findings = pd.DataFrame(details)
    overview = []
    severity_order = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    for app_id, name, _ in apps:
        sub = findings[findings.application_id == app_id]
        severity = max(sub.severity_label, key=lambda s: severity_order[s]) if len(sub) else "None"
        overview.append({
            "application_id": app_id, "application_name": name,
            "finding_count": len(sub), "affected_components": sub.bom_ref.nunique(),
            "risk_flag": "KNOWN_VULNERABILITY" if len(sub) else "NO_MATCH_IN_QUERIED_OSV",
            "severity_label": severity,
            "max_cvss_score": float(sub.cvss_score.max()) if len(sub) else None,
            "inventory_snapshot_sha256": app_sha[app_id],
        })
    application_overview = pd.DataFrame(overview)

    nodes, edges = {}, {}
    def node(node_id, typ, label, sha=None):
        nodes[node_id] = {"node_id": node_id, "node_type": typ, "label": label, "source_sha256": sha}
    def edge(src, rel, dst, sha=None, osv_sha=None):
        edges[(src, rel, dst)] = {"source_id": src, "relation": rel, "target_id": dst,
                                 "sbom_sha256": sha, "osv_query_sha256": osv_sha}
    for app_id, name, _ in apps:
        sha = app_sha[app_id]
        root = f"component:{sha}:root"
        node(f"app:{app_id}", "Application", name)
        node(root, "ComponentVersion", name, sha)
        edge(f"app:{app_id}", "HAS_INVENTORY", root, sha)
    for row in details:
        sha, ref, cve = row["sbom_sha256"], row["bom_ref"], row["vulnerability_id"]
        cmp_node = f"component:{sha}:{ref}"
        vuln_node = f"vuln:{cve}"
        node(cmp_node, "ComponentVersion", f"{row['component_name']}@{row['component_version']}", sha)
        node(vuln_node, "Vulnerability", cve)
        edge(f"component:{sha}:root", "DEPENDS_ON", cmp_node, sha)
        edge(cmp_node, "AFFECTED_BY", vuln_node, sha, row["osv_query_sha256"])
    graph_nodes = pd.DataFrame(nodes.values())
    graph_edges = pd.DataFrame(edges.values())
    assert set(graph_edges.source_id).union(graph_edges.target_id).issubset(set(graph_nodes.node_id))
    assert application_overview.finding_count.sum() == len(findings)
    return {
        "mart_application_overview": application_overview,
        "mart_application_findings": findings,
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
    }


if __name__ == "__main__":
    for table, df in build_mock_gold().items():
        print(f"\n{table} — {len(df)} rows")
        print(df.to_string(index=False, max_colwidth=32))
