"""Simple Streamlit interface over the dbt Gold views; ADC works on the GCP VM."""
import os
import streamlit as st
from google.cloud import bigquery

st.set_page_config(page_title="Knowledge MVP", layout="wide")
st.title("Enterprise knowledge — application exposure")
st.caption("OSV exact-version findings over CycloneDX inventories; synthetic apps in iteration 1")
project = os.environ.get("GCP_PROJECT")
if not project:
    st.error("GCP_PROJECT environment variable is missing")
    st.stop()

@st.cache_data(ttl=180)
def query(sql):
    client = bigquery.Client(project=project, location="EU")
    return [dict(row.items()) for row in client.query(sql).result()]

try:
    overview = query(f"""SELECT * FROM `{project}.vulnerability_gold.mart_application_overview`
                         ORDER BY application_name""")
    details = query(f"""SELECT * FROM `{project}.vulnerability_gold.mart_application_findings`
                        ORDER BY application_name, vulnerability_id""")
except Exception as exc:
    st.error(f"BigQuery query failed: {exc}")
    st.info("Run the Airflow DAG and verify the BigQuery Gold views first.")
    st.stop()

if not overview:
    st.warning("No applications loaded yet")
    st.stop()

st.subheader("Applications")
for app in overview:
    flag = "🔴" if app["risk_flag"] == "KNOWN_VULNERABILITY" else "⚪"
    st.write(f"{flag} **{app['application_name']}** — {app['finding_count']} findings; "
             f"{app['affected_components']} affected components; {app['risk_flag']}")

st.info("No match in queried OSV does not mean an application is secure. "
        "This MVP does not yet calculate validated CVSS severity.")

st.subheader("Findings and evidence")
selected = st.selectbox("Application", [a["application_name"] for a in overview])
chosen = [r for r in details if r["application_name"] == selected]
if not chosen:
    st.write("No known matches in the queried OSV responses for this inventory.")
for finding in chosen:
    with st.expander(f"{finding['component_name']}@{finding['component_version']} — "
                     f"{finding['vulnerability_id']}"):
        st.write("Package:", finding["package_name"])
        st.write("SBOM hash:", finding["sbom_sha256"])
        st.write("OSV query hash:", finding["osv_query_sha256"])
        st.write("SBOM GCS object:", finding["sbom_gcs_uri"])
        st.markdown(f"[OSV advisory]({finding['advisory_url']})")
