"""Vulnerability Intelligence — Local Streamlit Dashboard over the Gold Contract."""
from collections import defaultdict
import pandas as pd
import streamlit as st
from gold_contract_mock import build_mock_gold

st.set_page_config(page_title="Vulnerability Intelligence", layout="wide")


@st.cache_data
def load_gold() -> dict[str, pd.DataFrame]:
    """Single data-source swap point: replace with BigQuery loader later."""
    return build_mock_gold()


def get_app_subgraph(
    app_id: str, nodes: pd.DataFrame, edges: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Collect all nodes and edges reachable from a given application."""
    start_node = f"app:{app_id}"
    adj: dict[str, list[dict]] = defaultdict(list)
    for row in edges.to_dict(orient="records"):
        adj[row["source_id"]].append(row)

    visited_nodes = {start_node}
    visited_edges: list[dict] = []
    queue = [start_node]

    while queue:
        curr = queue.pop(0)
        for edge in adj.get(curr, []):
            visited_edges.append(edge)
            target = edge["target_id"]
            if target not in visited_nodes:
                visited_nodes.add(target)
                queue.append(target)

    sub_nodes = nodes[nodes["node_id"].isin(visited_nodes)].copy()
    sub_edges = pd.DataFrame(visited_edges) if visited_edges else edges.iloc[0:0].copy()
    return sub_nodes, sub_edges


def build_dependency_trees(
    app_id: str, sub_nodes: pd.DataFrame, sub_edges: pd.DataFrame
) -> list[str]:
    """Traverse graph_edges to build ASCII dependency paths ending in AFFECTED_BY."""
    labels = dict(zip(sub_nodes["node_id"], sub_nodes["label"]))
    adj: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for _, row in sub_edges.iterrows():
        adj[row["source_id"]].append((row["relation"], row["target_id"]))

    paths: list[list[tuple[str, str]]] = []

    def dfs(node_id: str, trail: list[tuple[str, str]]) -> None:
        for rel, target in adj.get(node_id, []):
            next_trail = trail + [(rel, target)]
            if rel == "AFFECTED_BY":
                paths.append(next_trail)
            else:
                dfs(target, next_trail)

    dfs(f"app:{app_id}", [])

    rendered: list[str] = []
    for trail in paths:
        # Skip the HAS_INVENTORY hop label duplication (App -> Root Component)
        steps = [step for step in trail if step[0] != "HAS_INVENTORY"]
        lines = [labels.get(f"app:{app_id}", app_id)]
        for depth, (rel, target) in enumerate(steps, start=1):
            indent = "  " * depth
            name = labels.get(target, target)
            if rel == "AFFECTED_BY":
                lines.append(f"{indent}└── AFFECTED_BY → {name}")
            else:
                lines.append(f"{indent}└── {name}")
        rendered.append("\n".join(lines))
    return rendered


def build_graphviz_dot(sub_nodes: pd.DataFrame, sub_edges: pd.DataFrame) -> str:
    """Render the application's subgraph using Streamlit's built-in Graphviz."""
    styles = {
        "Application": 'fillcolor="#dbeafe", color="#2563eb", fontcolor="#172554", shape="box", style="filled,rounded"',
        "ComponentVersion": 'fillcolor="#e0f2fe", color="#0284c7", fontcolor="#082f49", shape="box", style="filled,rounded"',
        "Vulnerability": 'fillcolor="#fee2e2", color="#dc2626", fontcolor="#7f1d1d", shape="box", style="filled,rounded"',
    }
    lines = [
        "digraph G {",
        '  rankdir="LR";',
        '  node [fontname="Helvetica", fontsize="11", penwidth="1.5"];',
        '  edge [fontname="Helvetica", fontsize="9", color="#64748b"];',
    ]
    for _, n in sub_nodes.iterrows():
        nid = n["node_id"].replace('"', '\\"')
        lbl = n["label"].replace('"', '\\"')
        style = styles.get(n["node_type"], 'shape="box"')
        lines.append(f'  "{nid}" [label="{lbl}", {style}];')

    for _, e in sub_edges.iterrows():
        src = e["source_id"].replace('"', '\\"')
        dst = e["target_id"].replace('"', '\\"')
        rel = e["relation"]
        color = "#dc2626" if rel == "AFFECTED_BY" else "#64748b"
        lines.append(f'  "{src}" -> "{dst}" [label=" {rel} ", color="{color}", fontcolor="{color}"];')

    lines.append("}")
    return "\n".join(lines)


# ------------------------------------------------------------------
# Load Data & Compute Enriched Overview
# ------------------------------------------------------------------
gold = load_gold()
overview = gold["mart_application_overview"].copy()
findings = gold["mart_application_findings"].copy()
nodes = gold["graph_nodes"].copy()
edges = gold["graph_edges"].copy()

has_v2_cvss = "v2_cvss_score" in findings.columns
if has_v2_cvss and not findings.empty:
    max_cvss = findings.groupby("application_id")["v2_cvss_score"].max()
    overview["v2_max_cvss"] = overview["application_id"].map(max_cvss)

overview = overview.sort_values(
    ["finding_count", "application_name"], ascending=[False, True]
).reset_index(drop=True)

# ------------------------------------------------------------------
# 1. Header & KPI Cards
# ------------------------------------------------------------------
title_col, badge_col = st.columns([5, 1])
with title_col:
    st.title("Vulnerability Intelligence")
    st.caption("Enterprise applications · OSV exact-version findings over CycloneDX inventories")
with badge_col:
    st.markdown(
        "<div style='text-align:right; padding-top:1.2rem;'>"
        "<span style='background:#fef3c7; color:#92400e; padding:4px 10px; "
        "border-radius:6px; font-weight:600; font-size:0.8rem;'>MOCK GOLD</span></div>",
        unsafe_allow_html=True,
    )

affected_apps_count = int((overview["finding_count"] > 0).sum())
c1, c2, c3, c4 = st.columns(4)
c1.metric("📦 Applications", len(overview))
c2.metric("🔎 Affected apps", affected_apps_count)
c3.metric("🛡️ Vulnerability findings", len(findings))
if has_v2_cvss:
    critical_apps = int((overview["v2_max_cvss"].fillna(0) >= 9.0).sum())
    c4.metric("🔴 Critical apps (v2 CVSS ≥ 9)", critical_apps)
else:
    c4.metric("🧩 Affected components", int(overview["affected_components"].sum()))

st.divider()

# ------------------------------------------------------------------
# 2. Application Risk Overview
# ------------------------------------------------------------------
st.subheader("Application risk overview")

display_overview = pd.DataFrame({
    "Application": overview["application_name"],
    "Status": overview["risk_flag"].map({
        "KNOWN_VULNERABILITY": "🔴 KNOWN_VULNERABILITY",
        "NO_MATCH_IN_QUERIED_OSV": "⚪ NO_MATCH_IN_QUERIED_OSV",
    }),
    "MVP Severity": overview["severity_label"],
    "Findings": overview["finding_count"],
    "Affected components": overview["affected_components"],
})
if has_v2_cvss:
    display_overview["Max CVSS (v2 preview)"] = overview["v2_max_cvss"]

st.dataframe(
    display_overview,
    use_container_width=True,
    hide_index=True,
    column_config={
        "Max CVSS (v2 preview)": st.column_config.NumberColumn(format="%.1f"),
    },
)

st.info(
    "**Interpretation:** `NO_MATCH_IN_QUERIED_OSV` does not mean an application is secure — "
    "it only means no match was found among the queried OSV advisories and installed versions. "
    "MVP baseline severity is `UNRATED`; CVSS scores shown are Iteration 2 previews."
)

st.divider()

# ------------------------------------------------------------------
# 3. Application Investigation
# ------------------------------------------------------------------
st.subheader("Application investigation")

selected_name = st.selectbox(
    "Select an application to inspect",
    overview["application_name"].tolist(),
)
selected_app = overview[overview["application_name"] == selected_name].iloc[0]
selected_id = selected_app["application_id"]
app_findings = findings[findings["application_id"] == selected_id].sort_values(
    "vulnerability_id"
)

m1, m2, m3 = st.columns(3)
m1.metric("Selected application", selected_name)
m2.metric("Findings", int(selected_app["finding_count"]))
m3.metric("Affected components", int(selected_app["affected_components"]))

sub_nodes, sub_edges = get_app_subgraph(selected_id, nodes, edges)

tab_findings, tab_evidence, tab_graph = st.tabs(
    ["Findings & dependency paths", "Evidence & traceability", "Knowledge graph"]
)

# --- Tab 1: Findings Table + Graph-Derived Dependency Paths ---
with tab_findings:
    if app_findings.empty:
        st.success("No known matches in the queried OSV responses for this inventory.")
    else:
        findings_table = pd.DataFrame({
            "Component": app_findings["component_name"],
            "Version": app_findings["component_version"],
            "Vulnerability": app_findings["vulnerability_id"],
            "MVP Severity": app_findings["severity_label"],
            "CVSS (v2)": app_findings["v2_cvss_score"] if has_v2_cvss else None,
            "Advisory": app_findings["advisory_url"],
        })
        st.dataframe(
            findings_table,
            use_container_width=True,
            hide_index=True,
            column_config={
                "CVSS (v2)": st.column_config.NumberColumn(format="%.1f"),
                "Advisory": st.column_config.LinkColumn(
                    "OSV Advisory", display_text="Open OSV ↗"
                ),
            },
        )

        st.markdown("#### Dependency paths (derived from `graph_edges`)")
        trees = build_dependency_trees(selected_id, sub_nodes, sub_edges)
        for tree in trees:
            st.code(tree, language="text")

# --- Tab 2: Evidence & Traceability ---
with tab_evidence:
    if app_findings.empty:
        st.write("No vulnerability evidence records for this application.")
    else:
        for _, row in app_findings.iterrows():
            with st.expander(
                f"{row['component_name']}@{row['component_version']} — {row['vulnerability_id']}",
                expanded=True,
            ):
                left, right = st.columns(2)
                with left:
                    st.markdown(f"**Package:** `{row['package_name']}`")
                    st.markdown(f"**Installed version:** `{row['component_version']}`")
                    st.markdown(f"**Match status:** `{row['finding_status']}`")
                    if pd.notna(row.get("v2_cvss_score")):
                        st.markdown(f"**CVSS (v2 preview):** `{row['v2_cvss_score']:.1f}`")
                    if pd.notna(row.get("v2_vulnerability_summary")):
                        st.markdown(f"**Summary (v2 preview):** {row['v2_vulnerability_summary']}")
                    st.markdown(f"**Advisory source:** [{row['vulnerability_id']}]({row['advisory_url']})")
                with right:
                    st.markdown(f"**SBOM SHA-256:** `{row['sbom_sha256']}`")
                    st.markdown(f"**OSV Query SHA-256:** `{row['osv_query_sha256']}`")
                    st.markdown(f"**Bronze GCS URI:** `{row['sbom_gcs_uri']}`")
                    st.markdown(f"**Inventory snapshot:** `{row['inventory_first_seen']}`")

# --- Tab 3: Knowledge Graph Diagram + Tables ---
with tab_graph:
    st.markdown(f"#### Relationship diagram — {selected_name}")
    st.graphviz_chart(build_graphviz_dot(sub_nodes, sub_edges), use_container_width=True)
    st.caption(
        "An `AFFECTED_BY` edge indicates a known OSV vulnerability match for the installed "
        "package version; it does not by itself prove runtime exploitability."
    )

    with st.expander("Inspect underlying Gold graph tables (`graph_nodes` & `graph_edges`)"):
        g1, g2 = st.columns(2)
        with g1:
            st.markdown(f"**`graph_nodes` ({len(sub_nodes)} rows)**")
            st.dataframe(sub_nodes, use_container_width=True, hide_index=True)
        with g2:
            st.markdown(f"**`graph_edges` ({len(sub_edges)} rows)**")
            st.dataframe(sub_edges, use_container_width=True, hide_index=True)
