"""Original Gold dashboard, adapted to BigQuery and release-level selection.

Read Gold only. No contact OSV or safety inference without vulns count.
"""
import json
import os
import streamlit as st
from google.cloud import bigquery
from config import ROOT, settings

st.set_page_config(page_title='Vulnerability Intelligence',layout='wide')
st.title('Vulnerability Intelligence')
# Load .env before choosing the mode.
from dotenv import load_dotenv
load_dotenv(ROOT/'.env')
demo = os.getenv('MVP_DEMO','0')=='1'
project,_,dataset,location = settings(demo)
st.caption(('Synthetic offline fixtures' if demo else 'Real Maven release inventories') +
           ' · BigQuery / dbt · No downstream vulnerability API calls')

@st.cache_data(ttl=60)
def query_gold(project,dataset,location,publication_id,sql,sha=None):
    """Parameterized inventory filters; avoid downloading the full graph."""
    cfg=bigquery.QueryJobConfig(query_parameters=[] if sha is None else [bigquery.ScalarQueryParameter('sha','STRING',sha)])
    return bigquery.Client(project=project).query(sql,job_config=cfg,location=location).to_dataframe()

prefix=f'{project}.{dataset}'
def read(sql,sha=None):
    return query_gold(project,dataset,location,publication_id,sql,sha)

try:
    # Check uncached status before reading marts. Cached rows are scoped to
    # publication ID to avoid presenting a prior generation after rebuilding.
    publication=bigquery.Client(project=project).query(f'SELECT * FROM `{prefix}.gold_publication`',location=location).result()
    status_rows=list(publication)
    if len(status_rows)!=1 or status_rows[0].status!='SUCCESS':
        st.warning('Gold is not published: the last build is incomplete or failed. Run build_gold.py.')
        st.stop()
    publication_id=status_rows[0].run_id
    st.caption(f'Gold last published: {status_rows[0].status_at} UTC')
    overview=read(f'SELECT * FROM `{prefix}.mart_application_overview` ORDER BY application_id,commit_at,release_tag')
except Exception as exc:
    st.error(f'Gold is unavailable: {exc}. Run build_gold.py successfully before opening the dashboard.')
    st.stop()
if overview.empty:
    st.warning('No release inventories are available. No vulnerability assessment can be made.')
    st.stop()
if not demo:
    expected={(a['application_id'],t) for a in json.loads((ROOT/'applications.json').read_text()) for t in a['releases']}
    actual=set(zip(overview.application_id,overview.release_tag))
    missing=expected-actual
    if missing:
        st.warning(f'{len(missing)} of {len(expected)} planned release inventories are missing or not loaded; not assessed: '+', '.join(f'{a}/{t}' for a,t in sorted(missing)))
a,b,c=st.columns(3)
a.metric('Applications',overview.application_id.nunique())
b.metric('Affected applications',overview.loc[overview.finding_count>0,'application_id'].nunique())
c.metric('Known matches across releases',int(overview.finding_count.sum()))
st.caption('Each row is one release evaluated using currently available OSV knowledge, not an assessment as of its release date.')
if (overview.risk_flag=='QUERY_INCOMPLETE').any():
    st.warning('Incomplete query coverage: match counts are observed lower bounds, not evidence of safety. Failed, skipped or missing queries are unknown.')
st.subheader('Application overview')
st.dataframe(overview,hide_index=True,use_container_width=True)
labels={row.inventory_snapshot_sha256:f'{row.application_name} · {row.release_tag} ({row.application_id})' for row in overview.itertuples()}
selected=st.selectbox('Investigate application / release',list(labels),format_func=labels.get)
# Minimal historical dimension: compare the three release rows of the selected app.
app=overview.loc[overview.inventory_snapshot_sha256==selected,'application_id'].iloc[0]
if not demo:
    st.subheader('Release comparison — current OSV knowledge')
    st.dataframe(overview.loc[overview.application_id==app,['release_tag','commit_at','finding_count','affected_components','components_queried','components_to_query','risk_flag','last_evaluated_at']],hide_index=True,use_container_width=True)
st.subheader('Vulnerability findings and evidence')
findings=read(f'SELECT * FROM `{prefix}.mart_application_findings` WHERE sbom_sha256=@sha ORDER BY vulnerability_id,bom_ref',selected)
if findings.empty:
    risk=overview.loc[overview.inventory_snapshot_sha256==selected,'risk_flag'].iloc[0]
    st.info('Assessment incomplete; no confirmed matches in the available evidence.' if risk=='QUERY_INCOMPLETE' else 'No known matches in the completed OSV queries; not proof of safety.')
st.dataframe(findings,hide_index=True,use_container_width=True)
with st.expander('Knowledge graph tables'):
    if st.checkbox('Load graph for selected release'):
        # Preserve the existing graph tables; bound their transfer and disclose truncation.
        edges=read(f'SELECT * FROM `{prefix}.graph_edges` WHERE sbom_sha256=@sha ORDER BY source_id,target_id,relation LIMIT 2001',selected)
        nodes=read(f'''SELECT * FROM `{prefix}.graph_nodes` WHERE source_sha256=@sha OR node_id IN
         (SELECT target_id FROM `{prefix}.graph_edges` WHERE sbom_sha256=@sha AND relation='AFFECTED_BY') ORDER BY node_id LIMIT 2001''',selected)
        if len(edges)>2000 or len(nodes)>2000:
            st.warning('Display limited to 2,000 rows per graph table. Full data remains in BigQuery.')
        st.write('Nodes'); st.dataframe(nodes.head(2000),hide_index=True,use_container_width=True)
        st.write('Edges'); st.dataframe(edges.head(2000),hide_index=True,use_container_width=True)
