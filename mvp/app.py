"""Vulnerability Intelligence Dashboard — Gold Marts & Knowledge Graph.

Read Gold only. No contact OSV or safety inference without vulns count.
"""
import json
import os
import streamlit as st
from google.cloud import bigquery
from config import ROOT, settings
from dotenv import load_dotenv

# Page configuration
st.set_page_config(
    page_title='Vulnerability Intelligence',
    page_icon='🛡️',
    layout='wide',
    initial_sidebar_state='expanded'
)

# Load environment configuration
load_dotenv(ROOT / '.env')
demo = os.getenv('MVP_DEMO', '0') == '1'
project, _, dataset, location = settings(demo)

# Header
st.title('🛡️ Vulnerability Intelligence Dashboard')
mode_label = 'Synthetic Offline Fixtures (Demo)' if demo else 'Real Maven Release Inventories (Live)'
st.caption(f'**{mode_label}** · BigQuery & dbt Gold Marts · Zero downstream vulnerability API calls')

# Sidebar configuration & metadata
with st.sidebar:
    st.header('⚙️ Pipeline Details')
    st.markdown(f"**GCP Project:** `{project}`")
    st.markdown(f"**BigQuery Dataset:** `{dataset}`")
    st.markdown(f"**Region:** `{location}`")
    st.markdown(f"**Mode:** {'`DEMO`' if demo else '`PRODUCTION`'}")
    st.divider()
    st.info(
        "💡 **Enterprise Knowledge Pipeline:**\n"
        "Evaluates historical release inventories against OSV intelligence, "
        "calculates BFS shortest dependency paths, and visualizes knowledge graphs."
    )

@st.cache_data(ttl=60)
def query_gold(project, dataset, location, publication_id, sql, sha=None):
    """Parameterized inventory filters; avoid downloading the full graph."""
    cfg = bigquery.QueryJobConfig(
        query_parameters=[] if sha is None else [bigquery.ScalarQueryParameter('sha', 'STRING', sha)]
    )
    return bigquery.Client(project=project).query(sql, job_config=cfg, location=location).to_dataframe()

prefix = f'{project}.{dataset}'
def read(sql, sha=None):
    return query_gold(project, dataset, location, publication_id, sql, sha)

# Publication guard check
try:
    publication = bigquery.Client(project=project).query(
        f'SELECT * FROM `{prefix}.gold_publication`', location=location
    ).result()
    status_rows = list(publication)
    if len(status_rows) != 1 or status_rows[0].status != 'SUCCESS':
        st.warning('⚠️ Gold is not published: the last build is incomplete or failed. Run build_gold.py.')
        st.stop()
    publication_id = status_rows[0].run_id
    st.sidebar.success(f"**Gold Published:** {status_rows[0].status_at} UTC")
    overview = read(f'SELECT * FROM `{prefix}.mart_application_overview` ORDER BY application_id, commit_at, release_tag')
except Exception as exc:
    st.error(f'❌ Gold is unavailable: {exc}. Run build_gold.py successfully before opening the dashboard.')
    st.stop()

if overview.empty:
    st.warning('No release inventories are available. No vulnerability assessment can be made.')
    st.stop()

if not demo:
    expected = {(a['application_id'], t) for a in json.loads((ROOT / 'applications.json').read_text()) for t in a['releases']}
    actual = set(zip(overview.application_id, overview.release_tag))
    missing = expected - actual
    if missing:
        st.warning(
            f'⚠️ {len(missing)} of {len(expected)} planned release inventories are missing or not loaded: ' +
            ', '.join(f'{a}/{t}' for a, t in sorted(missing))
        )

# KPI metric cards
kpi1, kpi2, kpi3, kpi4 = st.columns(4)
total_apps = overview.application_id.nunique()
affected_apps = overview.loc[overview.finding_count > 0, 'application_id'].nunique()
total_matches = int(overview.finding_count.sum())
total_releases = len(overview)

kpi1.metric('🏢 Applications', total_apps)
kpi2.metric('📦 Assessed Releases', total_releases)
kpi3.metric('🚨 Affected Applications', affected_apps)
kpi4.metric('🔍 Total Known Matches', total_matches)

if (overview.risk_flag == 'QUERY_INCOMPLETE').any():
    st.warning('⚠️ Incomplete query coverage detected: match counts are observed lower bounds. Failed, skipped, or missing queries are unknown.')

st.divider()

# Interactive Application & Release selector
labels = {
    row.inventory_snapshot_sha256: f'{row.application_name} · Release {row.release_tag} ({row.application_id})'
    for row in overview.itertuples()
}
selected = st.selectbox('🎯 **Select Application / Release to investigate:**', list(labels), format_func=labels.get)
app_id = overview.loc[overview.inventory_snapshot_sha256 == selected, 'application_id'].iloc[0]
app_row = overview.loc[overview.inventory_snapshot_sha256 == selected].iloc[0]

# Dashboard organized into tabs
tab1, tab2, tab3 = st.tabs([
    '📊 Portfolio & Release Comparison',
    '🔍 Vulnerability Findings & Paths',
    '🕸️ Knowledge Graph'
])

with tab1:
    st.subheader('Application Portfolio Overview')
    st.dataframe(
        overview,
        column_config={
            'inventory_snapshot_sha256': st.column_config.TextColumn('Snapshot SHA-256', width='small'),
            'finding_count': st.column_config.NumberColumn('Findings', format='%d ⚠️'),
            'affected_components': st.column_config.NumberColumn('Affected Components', format='%d'),
            'components_queried': st.column_config.NumberColumn('Components Queried', format='%d'),
            'components_to_query': st.column_config.NumberColumn('Total Components', format='%d'),
            'commit_at': st.column_config.TextColumn('Commit Date'),
            'risk_flag': st.column_config.TextColumn('Risk Status')
        },
        hide_index=True,
        use_container_width=True
    )

    if not demo:
        st.subheader(f'Release Progression — `{app_row.application_name}`')
        st.caption('Compare vulnerability exposure across historical releases using currently available OSV intelligence.')
        st.dataframe(
            overview.loc[
                overview.application_id == app_id,
                ['release_tag', 'commit_at', 'finding_count', 'affected_components', 'components_queried', 'components_to_query', 'risk_flag', 'last_evaluated_at']
            ],
            column_config={
                'release_tag': st.column_config.TextColumn('Release Tag'),
                'finding_count': st.column_config.NumberColumn('Known Matches', format='%d'),
                'risk_flag': st.column_config.TextColumn('Status')
            },
            hide_index=True,
            use_container_width=True
        )

with tab2:
    st.subheader(f'Vulnerability Findings for `{app_row.application_name}` ({app_row.release_tag})')
    findings = read(
        f'SELECT * FROM `{prefix}.mart_application_findings` WHERE sbom_sha256=@sha ORDER BY vulnerability_id, bom_ref',
        selected
    )
    if findings.empty:
        risk = app_row.risk_flag
        if risk == 'QUERY_INCOMPLETE':
            st.info('ℹ️ Assessment incomplete; no confirmed matches in available evidence.')
        else:
            st.success('✅ No known matches in the completed OSV queries (at current evaluation time).')
    else:
        st.dataframe(
            findings,
            column_config={
                'advisory_url': st.column_config.LinkColumn('OSV Advisory', display_text='View on OSV.dev ↗'),
                'vulnerability_id': st.column_config.TextColumn('Vulnerability ID'),
                'component_name': st.column_config.TextColumn('Component'),
                'component_version': st.column_config.TextColumn('Version'),
                'v2_dependency_path': st.column_config.TextColumn('Shortest Dependency Path (BFS)'),
                'v2_vulnerability_summary': st.column_config.TextColumn('Summary'),
                'finding_status': st.column_config.TextColumn('Status')
            },
            hide_index=True,
            use_container_width=True
        )

with tab3:
    st.subheader(f'Knowledge Graph — `{app_row.application_name}` ({app_row.release_tag})')
    st.caption('Explore dependencies, components, and vulnerability relationships directly from the graph model.')
    if st.checkbox('Load graph tables for selected release'):
        edges = read(
            f'SELECT * FROM `{prefix}.graph_edges` WHERE sbom_sha256=@sha ORDER BY source_id, target_id, relation LIMIT 2001',
            selected
        )
        nodes = read(
            f'''SELECT * FROM `{prefix}.graph_nodes` WHERE source_sha256=@sha OR node_id IN
             (SELECT target_id FROM `{prefix}.graph_edges` WHERE sbom_sha256=@sha AND relation='AFFECTED_BY') ORDER BY node_id LIMIT 2001''',
            selected
        )
        if len(edges) > 2000 or len(nodes) > 2000:
            st.warning('⚠️ Display limited to 2,000 rows per table. Full graph remains in BigQuery.')

        col_nodes, col_edges = st.columns(2)
        with col_nodes:
            st.markdown(f"**Nodes ({len(nodes)})**")
            st.dataframe(nodes.head(2000), hide_index=True, use_container_width=True)
        with col_edges:
            st.markdown(f"**Edges ({len(edges)})**")
            st.dataframe(edges.head(2000), hide_index=True, use_container_width=True)
