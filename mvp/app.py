"""Vulnerability Intelligence Dashboard — Gold Marts & Knowledge Graph.

Read Gold only. No downstream OSV calls or safety inference without query coverage.
"""
from collections import defaultdict, deque
import html
import json
import os
import tempfile

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv
from google.cloud import bigquery
from pyvis.network import Network

from config import ROOT, settings

# ---------------------------------------------------------------------------
# Page Configuration & Global Styling
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title='Vulnerability Intelligence',
    page_icon='🛡️',
    layout='wide',
    initial_sidebar_state='expanded',
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

    /* Crisp technical typography without touching Streamlit Material icons */
    html, body, .stApp, p, label, input, textarea, h1, h2, h3, h4, h5, h6, th, td {
        font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }
    [data-testid="stIconMaterial"], .material-symbols-rounded, span[translate="no"] {
        font-family: 'Material Symbols Rounded' !important;
    }
    [data-testid="stMetricValue"], code, pre, .bfs-chain {
        font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace !important;
        font-variant-numeric: tabular-nums;
    }
    h1, h2, h3, h4 {
        letter-spacing: -0.02em;
        font-weight: 600;
    }

    /* Refined top spacing */
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2.5rem;
    }
    /* Subtle badge pills */
    .badge {
        display: inline-block;
        padding: 0.2rem 0.65rem;
        border-radius: 9999px;
        font-size: 0.78rem;
        font-weight: 600;
        letter-spacing: 0.02em;
        margin-right: 0.4rem;
    }
    .badge-live { background: rgba(16, 185, 129, 0.16); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.35); }
    .badge-demo { background: rgba(245, 158, 11, 0.16); color: #FBBF24; border: 1px solid rgba(245, 158, 11, 0.35); }
    .badge-meta { background: rgba(59, 130, 246, 0.14); color: #93C5FD; border: 1px solid rgba(59, 130, 246, 0.3); }

    /* BFS Dependency Path Breadcrumb */
    .bfs-chain {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 0.45rem;
        padding: 0.85rem 1rem;
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 0.5rem;
        margin-top: 0.5rem;
        margin-bottom: 0.75rem;
        font-size: 0.82rem;
    }
    .bfs-node {
        padding: 0.22rem 0.55rem;
        border-radius: 0.35rem;
        background: #1E293B;
        color: #E2E8F0;
        border: 1px solid #334155;
    }
    .bfs-root {
        background: rgba(59, 130, 246, 0.2);
        color: #93C5FD;
        border-color: rgba(59, 130, 246, 0.45);
        font-weight: 600;
    }
    .bfs-vuln-pkg {
        background: rgba(249, 115, 22, 0.2);
        color: #FDBA74;
        border-color: rgba(249, 115, 22, 0.5);
        font-weight: 600;
    }
    .bfs-cve {
        background: rgba(239, 68, 68, 0.2);
        color: #FCA5A5;
        border-color: rgba(239, 68, 68, 0.5);
        font-weight: 600;
    }
    .bfs-arrow {
        color: #64748B;
        font-weight: 700;
    }

    /* Legend dots for Knowledge Graph */
    .legend-row {
        display: flex;
        flex-wrap: wrap;
        gap: 1.1rem;
        margin: 0.35rem 0 0.75rem 0;
        font-size: 0.84rem;
        color: #CBD5E1;
    }
    .legend-dot {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 0.4rem;
        vertical-align: middle;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Environment & Cached BigQuery Access
# ---------------------------------------------------------------------------
load_dotenv(ROOT / '.env')
demo = os.getenv('MVP_DEMO', '0') == '1'
project, _, dataset, location = settings(demo)
prefix = f'{project}.{dataset}'


@st.cache_resource
def get_bq_client(project_id: str) -> bigquery.Client:
    """Reuse a single BigQuery client across reruns."""
    return bigquery.Client(project=project_id)


@st.cache_data(ttl=120)
def query_gold(project_id: str, dataset_name: str, bq_location: str, publication_id: str, sql: str, sha: str | None = None) -> pd.DataFrame:
    """Parameterized Gold query with publication-keyed caching."""
    cfg = bigquery.QueryJobConfig(
        query_parameters=[] if sha is None else [bigquery.ScalarQueryParameter('sha', 'STRING', sha)]
    )
    return get_bq_client(project_id).query(sql, job_config=cfg, location=bq_location).to_dataframe()


def read_gold(sql: str, sha: str | None = None) -> pd.DataFrame:
    return query_gold(project, dataset, location, publication_id, sql, sha)


# ---------------------------------------------------------------------------
# Publication Guard Check
# ---------------------------------------------------------------------------
try:
    pub_rows = list(
        get_bq_client(project).query(f'SELECT * FROM `{prefix}.gold_publication`', location=location).result()
    )
    if len(pub_rows) != 1 or pub_rows[0].status != 'SUCCESS':
        st.warning('Gold is not published: the last build is incomplete or failed. Run `build_gold.py`.')
        st.stop()
    publication_id = pub_rows[0].run_id
    published_at = pub_rows[0].status_at
    overview_raw = read_gold(
        f'SELECT * FROM `{prefix}.mart_application_overview` ORDER BY application_id, commit_at, release_tag'
    )
except Exception as exc:
    st.error(f'Gold layer is unavailable: {exc}. Run `build_gold.py` successfully before opening the dashboard.')
    st.stop()

if overview_raw.empty:
    st.warning('No release inventories are available. No vulnerability assessment can be made.')
    st.stop()

# ---------------------------------------------------------------------------
# Enrich Overview DataFrame for Clean Presentation
# ---------------------------------------------------------------------------
RISK_LABELS = {
    'KNOWN_VULNERABILITY': '🔴 Vulnerable',
    'QUERY_INCOMPLETE': '🟡 Incomplete',
    'NO_MATCH_IN_QUERIED_OSV': '🟢 No Known Match',
}
RISK_COLORS = {
    '🔴 Vulnerable': '#EF4444',
    '🟡 Incomplete': '#F59E0B',
    '🟢 No Known Match': '#10B981',
}

overview = overview_raw.copy()
for _num_col in ('finding_count', 'affected_components', 'components_queried', 'components_to_query'):
    if _num_col in overview.columns:
        overview[_num_col] = pd.to_numeric(overview[_num_col], errors='coerce').fillna(0).astype(int)
overview['coverage_pct'] = overview.apply(
    lambda r: (100.0 * r['components_queried'] / r['components_to_query']) if r['components_to_query'] else 0.0,
    axis=1,
)
overview['status_label'] = overview['risk_flag'].map(RISK_LABELS).fillna(overview['risk_flag'])
overview['release_label'] = overview['application_name'] + ' · ' + overview['release_tag'].astype(str)
overview['commit_dt'] = pd.to_datetime(overview['commit_at'], utc=True, errors='coerce')
overview['commit_date'] = overview['commit_dt'].dt.strftime('%Y-%m-%d').fillna('—')

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
pub_str = published_at.strftime('%Y-%m-%d %H:%M UTC') if hasattr(published_at, 'strftime') else str(published_at)
mode_badge = (
    '<span class="badge badge-demo">DEMO · Synthetic Offline Fixtures</span>'
    if demo
    else '<span class="badge badge-live">LIVE · Real Maven Release Inventories</span>'
)

st.markdown('## Vulnerability Intelligence Dashboard')
st.markdown(
    f'{mode_badge}'
    f'<span class="badge badge-meta">Gold Published: {html.escape(pub_str)}</span>'
    f'<span class="badge badge-meta">BigQuery & dbt Gold Marts</span>',
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar — Global Portfolio Filters & Collapsible Lineage
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header('Portfolio Filters')
    all_apps = sorted(overview['application_name'].dropna().unique().tolist())
    selected_apps = st.multiselect(
        'Applications',
        options=all_apps,
        default=all_apps,
        help='Filter the Executive Portfolio view and release list.',
    )

    all_statuses = list(overview['status_label'].unique())
    selected_statuses = st.multiselect(
        'Risk Status',
        options=all_statuses,
        default=all_statuses,
    )

    st.divider()
    with st.expander('Pipeline & Data Lineage', expanded=False):
        st.markdown(f'**GCP Project:** `{project}`')
        st.markdown(f'**Gold Dataset:** `{dataset}`')
        st.markdown(f'**Region:** `{location}`')
        st.markdown(f'**Mode:** `{"DEMO" if demo else "PRODUCTION"}`')
        st.markdown(f'**Publication ID:** `{publication_id[:12]}…`')
        st.markdown(f'**Published At:** `{pub_str}`')
        st.caption(
            'Reads Gold marts exclusively. Zero live OSV API calls are made by this UI; '
            'all dependency paths are precomputed via BFS.'
        )

filtered_overview = overview[
    overview['application_name'].isin(selected_apps) & overview['status_label'].isin(selected_statuses)
].copy()

if filtered_overview.empty:
    st.info('No releases match the current sidebar filters. Adjust the Application or Risk Status filters.')
    st.stop()

# ---------------------------------------------------------------------------
# Executive KPI Strip (Bordered Cards with Contextual Subtext)
# ---------------------------------------------------------------------------
total_apps = filtered_overview['application_id'].nunique()
affected_apps = filtered_overview.loc[filtered_overview['finding_count'] > 0, 'application_id'].nunique()
total_releases = len(filtered_overview)
affected_releases = int((filtered_overview['finding_count'] > 0).sum())
total_matches = int(filtered_overview['finding_count'].sum())
total_affected_pkgs = int(filtered_overview['affected_components'].sum())
queried = int(filtered_overview['components_queried'].sum())
to_query = int(filtered_overview['components_to_query'].sum())
coverage_pct = (100.0 * queried / to_query) if to_query else 0.0

planned_count = None
missing_releases: set[tuple[str, str]] = set()
if not demo:
    expected = {
        (a['application_id'], t)
        for a in json.loads((ROOT / 'applications.json').read_text())
        for t in a['releases']
    }
    planned_count = len(expected)
    actual = set(zip(overview['application_id'], overview['release_tag']))
    missing_releases = expected - actual

k1, k2, k3, k4, k5 = st.columns(5)
with k1:
    with st.container(border=True):
        st.metric('Applications', total_apps, delta=f'{affected_apps} affected', delta_color='inverse' if affected_apps else 'off')
with k2:
    with st.container(border=True):
        delta_rel = f'{planned_count} planned' if planned_count is not None else 'Demo fixtures'
        st.metric('Assessed Releases', total_releases, delta=delta_rel, delta_color='off')
with k3:
    with st.container(border=True):
        pct_aff = (100.0 * affected_releases / total_releases) if total_releases else 0.0
        st.metric('Affected Releases', affected_releases, delta=f'{pct_aff:.0f}% of assessed', delta_color='inverse' if affected_releases else 'off')
with k4:
    with st.container(border=True):
        st.metric('Known Matches', f'{total_matches:,}', delta=f'{total_affected_pkgs:,} affected pkgs', delta_color='inverse' if total_matches else 'off')
with k5:
    with st.container(border=True):
        st.metric('Query Coverage', f'{coverage_pct:.1f}%', delta=f'{queried:,} / {to_query:,} comps', delta_color='normal' if coverage_pct >= 99.0 else 'inverse')

# Compact Data Quality Notices
if missing_releases:
    st.warning(
        f'{len(missing_releases)} of {planned_count} planned release inventories are not loaded: '
        + ', '.join(f'{a}/{t}' for a, t in sorted(missing_releases))
    )
if (filtered_overview['risk_flag'] == 'QUERY_INCOMPLETE').any():
    st.warning(
        'Incomplete query coverage detected on one or more releases: match counts are observed lower bounds. '
        'Failed, skipped, or missing OSV queries represent unassessed risk.'
    )

# ---------------------------------------------------------------------------
# Shared Release Selector State (Used by Tabs 2 & 3)
# ---------------------------------------------------------------------------
release_options = filtered_overview['inventory_snapshot_sha256'].tolist()
release_labels = {
    row.inventory_snapshot_sha256: (
        f'{row.application_name} · {row.release_tag}  '
        f'({int(row.finding_count)} matches · {row.coverage_pct:.0f}% coverage)'
    )
    for row in filtered_overview.itertuples()
}

if 'selected_release_sha' not in st.session_state or st.session_state.selected_release_sha not in release_options:
    # Default to the release with the highest finding count for immediate relevance
    top_sha = filtered_overview.sort_values('finding_count', ascending=False)['inventory_snapshot_sha256'].iloc[0]
    st.session_state.selected_release_sha = top_sha


def sync_release(source_key: str) -> None:
    st.session_state.selected_release_sha = st.session_state[source_key]


def render_bfs_breadcrumb(path_text: str | None, vuln_id: str) -> str:
    """Render a clean HTML dependency chain from root to vulnerability."""
    if not path_text or pd.isna(path_text):
        return (
            '<div class="bfs-chain">'
            '<span class="bfs-node">Dependency path unavailable</span>'
            '<span class="bfs-arrow">→</span>'
            f'<span class="bfs-node bfs-cve">{html.escape(str(vuln_id))}</span>'
            '</div>'
        )
    parts = [p.strip() for p in str(path_text).split(' > ') if p.strip()]
    chips = []
    for idx, part in enumerate(parts):
        cls = 'bfs-node bfs-root' if idx == 0 else ('bfs-node bfs-vuln-pkg' if idx == len(parts) - 1 else 'bfs-node')
        chips.append(f'<span class="{cls}">{html.escape(part)}</span>')
    chips.append(f'<span class="bfs-node bfs-cve">{html.escape(str(vuln_id))}</span>')
    return '<div class="bfs-chain">' + '<span class="bfs-arrow">→</span>'.join(chips) + '</div>'


def build_vulnerable_subgraph(nodes_df: pd.DataFrame, edges_df: pd.DataFrame, vulnerable_only: bool, search_term: str, max_nodes: int = 160):
    """Extract a readable subgraph (vulnerable reachability paths by default)."""
    if edges_df.empty or nodes_df.empty:
        return pd.DataFrame(), pd.DataFrame()

    node_lookup = nodes_df.set_index('node_id').to_dict('index')
    vuln_edges = edges_df[edges_df['relation'] == 'AFFECTED_BY']

    if vulnerable_only:
        if vuln_edges.empty:
            return pd.DataFrame(), pd.DataFrame()
        # Reverse adjacency map to walk from vulnerable components back to Application Root
        parents = defaultdict(set)
        for row in edges_df.itertuples():
            if row.relation in ('DEPENDS_ON', 'HAS_INVENTORY'):
                parents[row.target_id].add(row.source_id)

        seed_vuln_edges = vuln_edges
        if search_term:
            term = search_term.lower()
            matching_nodes = {
                nid for nid, info in node_lookup.items()
                if term in str(info.get('label', '')).lower() or term in str(nid).lower()
            }
            seed_vuln_edges = vuln_edges[
                vuln_edges['source_id'].isin(matching_nodes) | vuln_edges['target_id'].isin(matching_nodes)
            ]
            if seed_vuln_edges.empty:
                return pd.DataFrame(), pd.DataFrame()

        kept_nodes = set(seed_vuln_edges['source_id']).union(set(seed_vuln_edges['target_id']))
        queue = deque(seed_vuln_edges['source_id'].unique())
        while queue:
            curr = queue.popleft()
            for p in parents.get(curr, ()):
                if p not in kept_nodes:
                    kept_nodes.add(p)
                    queue.append(p)

        sub_edges = edges_df[edges_df['source_id'].isin(kept_nodes) & edges_df['target_id'].isin(kept_nodes)].copy()
        if len(kept_nodes) > max_nodes:
            # Keep Application root + highest-degree vulnerable paths within cap
            priority_nodes = set(nodes_df.loc[nodes_df['node_type'] == 'Application', 'node_id'])
            priority_nodes.update(seed_vuln_edges['source_id'].tolist()[:40])
            priority_nodes.update(seed_vuln_edges['target_id'].tolist()[:60])
            remaining = [n for n in kept_nodes if n not in priority_nodes]
            kept_nodes = priority_nodes.union(remaining[: max(0, max_nodes - len(priority_nodes))])
            sub_edges = sub_edges[sub_edges['source_id'].isin(kept_nodes) & sub_edges['target_id'].isin(kept_nodes)]
        sub_nodes = nodes_df[nodes_df['node_id'].isin(kept_nodes)].copy()
        return sub_nodes, sub_edges

    # Full-release capped view
    sub_nodes = nodes_df.head(max_nodes).copy()
    kept = set(sub_nodes['node_id'])
    sub_edges = edges_df[edges_df['source_id'].isin(kept) & edges_df['target_id'].isin(kept)].copy()
    return sub_nodes, sub_edges


def render_pyvis_html(sub_nodes: pd.DataFrame, sub_edges: pd.DataFrame, vuln_comp_ids: set[str]) -> str:
    """Build an interactive PyVis dark-themed network HTML string."""
    net = Network(height='540px', width='100%', bgcolor='#0B1120', font_color='#E2E8F0', directed=True, cdn_resources='remote')
    net.set_options(
        """
        {
          "nodes": {
            "font": { "size": 12, "face": "IBM Plex Sans, system-ui, sans-serif", "color": "#E2E8F0" },
            "borderWidth": 1.5,
            "shadow": true
          },
          "edges": {
            "arrows": { "to": { "enabled": true, "scaleFactor": 0.65 } },
            "smooth": { "type": "cubicBezier", "roundness": 0.25 },
            "font": { "size": 9, "color": "#64748B", "align": "middle" }
          },
          "physics": {
            "barnesHut": {
              "gravitationalConstant": -4500,
              "centralGravity": 0.25,
              "springLength": 115,
              "springConstant": 0.04,
              "damping": 0.18
            },
            "stabilization": { "iterations": 120 }
          },
          "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "navigationButtons": false,
            "keyboard": true
          }
        }
        """
    )

    for row in sub_nodes.itertuples():
        nid = row.node_id
        ntype = row.node_type
        label = str(row.label or nid)
        short_label = label if len(label) <= 28 else label[:25] + '…'

        if ntype == 'Application':
            color, size, shape = '#3B82F6', 28, 'dot'
            role = 'Application Root'
        elif ntype == 'Vulnerability':
            color, size, shape = '#EF4444', 18, 'diamond'
            role = 'OSV Vulnerability'
        elif nid in vuln_comp_ids:
            color, size, shape = '#F97316', 21, 'dot'
            role = 'Vulnerable Component'
        else:
            color, size, shape = '#64748B', 14, 'dot'
            role = 'Intermediate Dependency'

        net.add_node(
            nid,
            label=short_label,
            title=f'{role}\n{label}',
            color=color,
            size=size,
            shape=shape,
        )

    for row in sub_edges.itertuples():
        edge_color = '#EF4444' if row.relation == 'AFFECTED_BY' else ('#3B82F6' if row.relation == 'HAS_INVENTORY' else '#475569')
        dashes = row.relation == 'AFFECTED_BY'
        net.add_edge(
            row.source_id,
            row.target_id,
            color=edge_color,
            dashes=dashes,
            title=row.relation,
            width=2.0 if row.relation == 'AFFECTED_BY' else 1.2,
        )

    with tempfile.NamedTemporaryFile(mode='r+', suffix='.html', delete=False, encoding='utf-8') as tmp:
        tmp_path = tmp.name
    try:
        net.save_graph(tmp_path)
        with open(tmp_path, 'r', encoding='utf-8') as f:
            raw_html = f.read()
        # Eliminate PyVis white iframe border, inline-canvas baseline gap, and HiDPI bottom-edge smear
        dark_frame_css = (
            '<style>'
            'html, body { margin: 0 !important; padding: 0 !important; background: #0B1120 !important; overflow: hidden !important; }'
            '.card { background: #0B1120 !important; border: 1px solid #1E293B !important; border-radius: 8px !important; margin: 0 !important; overflow: hidden !important; }'
            '#mynetwork { border: none !important; background: #0B1120 !important; overflow: hidden !important; }'
            '#mynetwork canvas { display: block !important; }'
            '</style></head>'
        )
        return raw_html.replace('</head>', dark_frame_css, 1)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# ---------------------------------------------------------------------------
# Main Navigation Tabs
# ---------------------------------------------------------------------------
tab1, tab2, tab3 = st.tabs([
    'Portfolio & Release Trends',
    'Vulnerability Triage & Paths',
    'Interactive Knowledge Graph',
])

# ===========================================================================
# TAB 1: EXECUTIVE PORTFOLIO & RELEASE TRENDS
# ===========================================================================
with tab1:
    chart_col1, chart_col2 = st.columns(2, gap='large')

    with chart_col1:
        st.subheader('Exposure by Release')
        st.caption('Known OSV vulnerability matches per assessed release inventory.')
        bar_data = filtered_overview.sort_values('finding_count', ascending=False)
        exposure_chart = (
            alt.Chart(bar_data)
            .mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4)
            .encode(
                x=alt.X('finding_count:Q', title='Known Vulnerability Matches'),
                y=alt.Y('release_label:N', sort='-x', title=None, axis=alt.Axis(labelLimit=220)),
                color=alt.Color(
                    'status_label:N',
                    title='Risk Status',
                    scale=alt.Scale(
                        domain=list(RISK_COLORS.keys()),
                        range=list(RISK_COLORS.values()),
                    ),
                    legend=alt.Legend(orient='bottom'),
                ),
                tooltip=[
                    alt.Tooltip('application_name:N', title='Application'),
                    alt.Tooltip('release_tag:N', title='Release'),
                    alt.Tooltip('finding_count:Q', title='Known Matches', format=','),
                    alt.Tooltip('affected_components:Q', title='Affected Components', format=','),
                    alt.Tooltip('coverage_pct:Q', title='Query Coverage %', format='.1f'),
                    alt.Tooltip('commit_date:N', title='Commit Date'),
                ],
            )
            .properties(height=max(260, len(bar_data) * 26))
        )
        st.altair_chart(exposure_chart, use_container_width=True)

    with chart_col2:
        st.subheader('Release Progression Over Time')
        st.caption('Historical vulnerability exposure across application releases.')
        trend_data = filtered_overview.dropna(subset=['commit_dt']).sort_values('commit_dt')
        if not trend_data.empty and trend_data['commit_dt'].nunique() > 1:
            trend_chart = (
                alt.Chart(trend_data)
                .mark_line(point=alt.OverlayMarkDef(size=70, filled=True), strokeWidth=2.5)
                .encode(
                    x=alt.X('commit_dt:T', title='Release Commit Date'),
                    y=alt.Y('finding_count:Q', title='Known Vulnerability Matches'),
                    color=alt.Color('application_name:N', title='Application', legend=alt.Legend(orient='bottom')),
                    tooltip=[
                        alt.Tooltip('application_name:N', title='Application'),
                        alt.Tooltip('release_tag:N', title='Release'),
                        alt.Tooltip('commit_date:N', title='Commit Date'),
                        alt.Tooltip('finding_count:Q', title='Known Matches', format=','),
                        alt.Tooltip('affected_components:Q', title='Affected Components', format=','),
                    ],
                )
                .properties(height=max(260, len(bar_data) * 26))
            )
            st.altair_chart(trend_chart, use_container_width=True)
        else:
            st.info('Not enough dated releases in the current filter to plot a timeline.')

    st.divider()

    hdr_l, hdr_r = st.columns([3, 1])
    with hdr_l:
        st.subheader('Release Portfolio Table')
    with hdr_r:
        show_tech_cols = st.toggle('Show technical provenance', value=False, key='tab1_tech_cols')

    curated_cols = [
        'application_name',
        'release_tag',
        'status_label',
        'finding_count',
        'affected_components',
        'coverage_pct',
        'components_to_query',
        'commit_date',
        'repository_url',
    ]
    tech_cols = [
        'components_queried',
        'failed_queries',
        'skipped_queries',
        'missing_queries',
        'git_commit',
        'inventory_snapshot_sha256',
        'last_evaluated_at',
    ]
    display_cols = curated_cols + (tech_cols if show_tech_cols else [])
    display_cols = [c for c in display_cols if c in filtered_overview.columns]

    st.dataframe(
        filtered_overview[display_cols],
        column_config={
            'application_name': st.column_config.TextColumn('Application'),
            'release_tag': st.column_config.TextColumn('Release'),
            'status_label': st.column_config.TextColumn('Risk Status'),
            'finding_count': st.column_config.NumberColumn('Known Matches', format='%d'),
            'affected_components': st.column_config.NumberColumn('Affected Pkgs', format='%d'),
            'coverage_pct': st.column_config.ProgressColumn('Query Coverage', format='%.1f%%', min_value=0, max_value=100),
            'components_to_query': st.column_config.NumberColumn('Total Pkgs', format='%d'),
            'commit_date': st.column_config.TextColumn('Commit Date'),
            'repository_url': st.column_config.LinkColumn('Repository', display_text='Open Repo ↗'),
            'inventory_snapshot_sha256': st.column_config.TextColumn('Snapshot SHA-256', width='small'),
        },
        hide_index=True,
        use_container_width=True,
    )

# ===========================================================================
# TAB 2: VULNERABILITY TRIAGE & BFS DEPENDENCY PATHS
# ===========================================================================
with tab2:
    sel_t2 = st.selectbox(
        'Select Release to Triage',
        options=release_options,
        index=release_options.index(st.session_state.selected_release_sha),
        format_func=release_labels.get,
        key='t2_release_select',
        on_change=sync_release,
        args=('t2_release_select',),
    )
    app_row = filtered_overview.loc[filtered_overview['inventory_snapshot_sha256'] == sel_t2].iloc[0]

    findings_raw = read_gold(
        f'SELECT * FROM `{prefix}.mart_application_findings` WHERE sbom_sha256=@sha ORDER BY vulnerability_id, bom_ref',
        sel_t2,
    )

    if findings_raw.empty:
        if app_row['risk_flag'] == 'QUERY_INCOMPLETE':
            st.info('Assessment is incomplete; no confirmed matches in available evidence.')
        else:
            st.success('No known vulnerability matches in the completed OSV queries for this release.')
    else:
        findings = findings_raw.copy()
        # Derive hop depth cleanly whether dependency_hops column is already materialized in BigQuery or not
        if 'dependency_hops' in findings.columns:
            findings['hops'] = findings['dependency_hops']
        else:
            findings['hops'] = findings['v2_dependency_path'].apply(
                lambda p: p.count(' > ') if isinstance(p, str) and p else None
            )
        findings['depth_category'] = findings['hops'].apply(
            lambda h: 'Path Unknown' if pd.isna(h) else ('Direct (1 hop)' if int(h) <= 1 else f'Transitive ({int(h)} hops)')
        )
        findings['depth_bucket'] = findings['hops'].apply(
            lambda h: 'Path Unknown' if pd.isna(h) else ('Direct (1 hop)' if int(h) <= 1 else 'Transitive (2+ hops)')
        )

        # Release-level mini KPI strip
        direct_cnt = int((findings['depth_bucket'] == 'Direct (1 hop)').sum())
        trans_cnt = int((findings['depth_bucket'] == 'Transitive (2+ hops)').sum())
        uniq_vulns = int(findings['vulnerability_id'].nunique())
        uniq_pkgs = int(findings['component_name'].nunique())

        m1, m2, m3, m4 = st.columns(4)
        m1.metric('Total Findings', f'{len(findings):,}')
        m2.metric('Unique Advisories', f'{uniq_vulns:,}')
        m3.metric('Direct / Transitive', f'{direct_cnt} / {trans_cnt}')
        m4.metric('Affected Packages', f'{uniq_pkgs:,}')

        st.divider()

        # Triage Controls Bar
        f_col1, f_col2, f_col3, f_col4 = st.columns([2.2, 2.2, 1.8, 1.0])
        with f_col1:
            search_q = st.text_input(
                'Search',
                placeholder='Filter by package, GHSA/CVE ID, or summary…',
                label_visibility='collapsed',
            )
        with f_col2:
            depth_choice = st.segmented_control(
                'Dependency Depth',
                options=['All', 'Direct (1 hop)', 'Transitive (2+ hops)'],
                default='All',
                label_visibility='collapsed',
            )
        with f_col3:
            triage_view = st.segmented_control(
                'View Mode',
                options=['Detailed Findings', 'Group by Package'],
                default='Detailed Findings',
                label_visibility='collapsed',
            )
        with f_col4:
            csv_bytes = findings.to_csv(index=False).encode('utf-8')
            st.download_button(
                'Export CSV',
                data=csv_bytes,
                file_name=f'{app_row.application_id}_{app_row.release_tag}_findings.csv',
                mime='text/csv',
                use_container_width=True,
            )

        filtered_findings = findings.copy()
        if search_q:
            q_low = search_q.strip().lower()
            mask = (
                filtered_findings['component_name'].astype(str).str.lower().str.contains(q_low, na=False)
                | filtered_findings['vulnerability_id'].astype(str).str.lower().str.contains(q_low, na=False)
                | filtered_findings['v2_vulnerability_summary'].astype(str).str.lower().str.contains(q_low, na=False)
            )
            if 'vulnerability_aliases' in filtered_findings.columns:
                mask = mask | filtered_findings['vulnerability_aliases'].astype(str).str.lower().str.contains(q_low, na=False)
            filtered_findings = filtered_findings[mask]

        if depth_choice and depth_choice != 'All':
            filtered_findings = filtered_findings[filtered_findings['depth_bucket'] == depth_choice]

        if filtered_findings.empty:
            st.info('No findings match your current search or depth filter.')
        elif triage_view == 'Group by Package':
            st.subheader('Remediation Leverage — Top Vulnerable Packages')
            st.caption('Upgrading the packages at the top of this chart resolves the highest number of known advisories.')
            pkg_agg = (
                filtered_findings.groupby(['component_name', 'component_version'], dropna=False)
                .agg(
                    finding_count=('vulnerability_id', 'count'),
                    min_hops=('hops', 'min'),
                    sample_ids=('vulnerability_id', lambda s: ', '.join(sorted(set(s))[:4]) + ('…' if len(set(s)) > 4 else '')),
                    shortest_path=('v2_dependency_path', 'first'),
                )
                .reset_index()
                .sort_values('finding_count', ascending=False)
            )
            pkg_agg['pkg_label'] = pkg_agg['component_name'].astype(str) + '@' + pkg_agg['component_version'].astype(str)

            top_pkgs = pkg_agg.head(12)
            pkg_chart = (
                alt.Chart(top_pkgs)
                .mark_bar(color='#F97316', cornerRadiusTopRight=4, cornerRadiusBottomRight=4)
                .encode(
                    x=alt.X('finding_count:Q', title='Known Advisories'),
                    y=alt.Y('pkg_label:N', sort='-x', title=None, axis=alt.Axis(labelLimit=260)),
                    tooltip=[
                        alt.Tooltip('component_name:N', title='Package'),
                        alt.Tooltip('component_version:N', title='Version'),
                        alt.Tooltip('finding_count:Q', title='Advisories'),
                        alt.Tooltip('min_hops:Q', title='Min Hops from Root'),
                        alt.Tooltip('sample_ids:N', title='Sample IDs'),
                    ],
                )
                .properties(height=max(240, len(top_pkgs) * 28))
            )
            st.altair_chart(pkg_chart, use_container_width=True)

            st.dataframe(
                pkg_agg[['component_name', 'component_version', 'finding_count', 'min_hops', 'sample_ids', 'shortest_path']],
                column_config={
                    'component_name': st.column_config.TextColumn('Component'),
                    'component_version': st.column_config.TextColumn('Version'),
                    'finding_count': st.column_config.NumberColumn('Advisories', format='%d'),
                    'min_hops': st.column_config.NumberColumn('Hops', format='%d'),
                    'sample_ids': st.column_config.TextColumn('Vulnerability IDs'),
                    'shortest_path': st.column_config.TextColumn('Shortest Dependency Path (BFS)'),
                },
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.caption(f'Showing {len(filtered_findings):,} findings. Click any row to inspect its BFS dependency path below.')
            curated_finding_cols = [
                'vulnerability_id',
                'component_name',
                'component_version',
                'depth_category',
                'v2_vulnerability_summary',
                'advisory_url',
            ]
            curated_finding_cols = [c for c in curated_finding_cols if c in filtered_findings.columns]

            selection = st.dataframe(
                filtered_findings[curated_finding_cols],
                column_config={
                    'vulnerability_id': st.column_config.TextColumn('Vulnerability ID'),
                    'component_name': st.column_config.TextColumn('Component'),
                    'component_version': st.column_config.TextColumn('Version'),
                    'depth_category': st.column_config.TextColumn('Depth'),
                    'v2_vulnerability_summary': st.column_config.TextColumn('Summary', width='large'),
                    'advisory_url': st.column_config.LinkColumn('OSV Advisory', display_text='View on OSV.dev ↗'),
                },
                hide_index=True,
                use_container_width=True,
                on_select='rerun',
                selection_mode='single-row',
                key='findings_table_select',
            )

            # Interactive Finding & BFS Path Inspector
            sel_rows = selection.selection.rows if selection and selection.selection else []
            inspected = filtered_findings.iloc[sel_rows[0]] if sel_rows else filtered_findings.iloc[0]

            with st.container(border=True):
                insp_top_l, insp_top_r = st.columns([3, 1])
                with insp_top_l:
                    st.markdown(f"#### `{inspected['vulnerability_id']}` — `{inspected['component_name']}@{inspected['component_version']}`")
                with insp_top_r:
                    st.link_button('Open OSV Advisory ↗', str(inspected['advisory_url']), use_container_width=True)

                summary_txt = inspected.get('v2_vulnerability_summary')
                st.write(summary_txt if pd.notna(summary_txt) and str(summary_txt).strip() else '_No summary provided in OSV advisory._')

                st.markdown('**Shortest Dependency Path (BFS)**')
                st.markdown(
                    render_bfs_breadcrumb(inspected.get('v2_dependency_path'), inspected['vulnerability_id']),
                    unsafe_allow_html=True,
                )

                with st.expander('Technical Provenance & Evidence', expanded=False):
                    p1, p2, p3 = st.columns(3)
                    p1.markdown(f"**BOM Ref:** `{inspected.get('bom_ref', '—')}`")
                    p2.markdown(f"**Published:** `{inspected.get('v2_published_at', '—')}`")
                    p3.markdown(f"**Evaluated:** `{inspected.get('evaluated_at', '—')}`")
                    st.markdown(f"**SBOM SHA-256:** `{inspected.get('sbom_sha256', '—')}`")
                    st.markdown(f"**OSV Query SHA-256:** `{inspected.get('osv_query_sha256', '—')}`")

# ===========================================================================
# TAB 3: INTERACTIVE KNOWLEDGE GRAPH
# ===========================================================================
with tab3:
    sel_t3 = st.selectbox(
        'Select Release for Knowledge Graph',
        options=release_options,
        index=release_options.index(st.session_state.selected_release_sha),
        format_func=release_labels.get,
        key='t3_release_select',
        on_change=sync_release,
        args=('t3_release_select',),
    )
    graph_app_row = filtered_overview.loc[filtered_overview['inventory_snapshot_sha256'] == sel_t3].iloc[0]

    g_ctrl1, g_ctrl2, g_ctrl3 = st.columns([2.2, 2.2, 1.4])
    with g_ctrl1:
        graph_scope = st.segmented_control(
            'Graph Scope',
            options=['Vulnerable Paths Only', 'Sampled Full Graph'],
            default='Vulnerable Paths Only',
            label_visibility='collapsed',
        )
    with g_ctrl2:
        graph_search = st.text_input(
            'Isolate Node',
            placeholder='Isolate a package or GHSA/CVE ID in graph…',
            label_visibility='collapsed',
            key='graph_node_search',
        )
    with g_ctrl3:
        max_graph_nodes = st.slider('Max nodes', min_value=30, max_value=250, value=120, step=10, label_visibility='collapsed')

    st.markdown(
        '<div class="legend-row">'
        '<span><span class="legend-dot" style="background:#3B82F6;"></span>Application Root</span>'
        '<span><span class="legend-dot" style="background:#64748B;"></span>Intermediate Dependency</span>'
        '<span><span class="legend-dot" style="background:#F97316;"></span>Vulnerable Component</span>'
        '<span><span class="legend-dot" style="background:#EF4444;"></span>OSV Vulnerability</span>'
        '</div>',
        unsafe_allow_html=True,
    )

    edges_df = read_gold(
        f'SELECT * FROM `{prefix}.graph_edges` WHERE sbom_sha256=@sha ORDER BY source_id, target_id, relation LIMIT 3000',
        sel_t3,
    )
    nodes_df = read_gold(
        f'''SELECT * FROM `{prefix}.graph_nodes` WHERE source_sha256=@sha OR node_id IN
         (SELECT target_id FROM `{prefix}.graph_edges` WHERE sbom_sha256=@sha AND relation='AFFECTED_BY')
         ORDER BY node_id LIMIT 3000''',
        sel_t3,
    )

    vuln_comp_ids = set(edges_df.loc[edges_df['relation'] == 'AFFECTED_BY', 'source_id'])
    sub_nodes, sub_edges = build_vulnerable_subgraph(
        nodes_df,
        edges_df,
        vulnerable_only=(graph_scope != 'Sampled Full Graph'),
        search_term=graph_search.strip(),
        max_nodes=max_graph_nodes,
    )

    if sub_nodes.empty:
        st.info(
            'No vulnerable graph paths match the current filter for this release. '
            'Switch to "Sampled Full Graph" or clear the search box to view dependencies.'
        )
    else:
        st.caption(
            f'Rendering **{len(sub_nodes):,} nodes** and **{len(sub_edges):,} edges** '
            f'(out of {len(nodes_df):,} nodes / {len(edges_df):,} edges in `{graph_app_row.application_name} · {graph_app_row.release_tag}`). '
            'Drag nodes, scroll to zoom, or hover for full labels.'
        )
        graph_html = render_pyvis_html(sub_nodes, sub_edges, vuln_comp_ids)
        components.html(graph_html, height=560, scrolling=False)

    with st.expander(f'Inspect Raw Graph Tables ({len(nodes_df):,} Nodes · {len(edges_df):,} Edges)', expanded=False):
        col_n, col_e = st.columns(2)
        with col_n:
            st.markdown('**Nodes**')
            st.dataframe(nodes_df.head(2000), hide_index=True, use_container_width=True)
        with col_e:
            st.markdown('**Edges**')
            st.dataframe(edges_df.head(2000), hide_index=True, use_container_width=True)
