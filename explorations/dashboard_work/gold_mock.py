import pandas as pd

# Simulated SHA-256 hashes representing the raw Bronze files
BILLING_SBOM_SHA = "a1b2c3d4e5f60001billing_sbom_sha256_placeholder"
ANALYTICS_SBOM_SHA = "f6e5d4c3b2a10002analytics_sbom_sha256_placeholder"
OSV_QUERY_SHA = "9988776655443322osv_query_sha256_placeholder"

# 1. Gold Table: mart_application_overview (1 row per application)
mart_application_overview = pd.DataFrame(
    [
        {
            "application_id": "app-billing",
            "application_name": "Billing",
            "sbom_sha256": BILLING_SBOM_SHA,
            "finding_count": 1,
            "risk_flag": "KNOWN_VULNERABILITY",
            "severity_label": "UNRATED",
        },
        {
            "application_id": "app-analytics",
            "application_name": "Analytics",
            "sbom_sha256": ANALYTICS_SBOM_SHA,
            "finding_count": 0,
            "risk_flag": "NO_MATCH_IN_QUERIED_OSV",
            "severity_label": "UNRATED",
        },
    ]
)

# 2. Gold Table: mart_application_findings (Drill-down evidence for matches)
mart_application_findings = pd.DataFrame(
    [
        {
            "application_id": "app-billing",
            "application_name": "Billing",
            "bom_ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "component_name": "log4j-core",
            "component_version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "vulnerability_id": "GHSA-jfh8-c2jp-5v3q",
            "advisory_url": "https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q",
            "sbom_sha256": BILLING_SBOM_SHA,
            "osv_query_sha256": OSV_QUERY_SHA,
            "gcs_uri": f"gs://your-project-knowledge-bronze/raw/sbom_billing/{BILLING_SBOM_SHA}.json",
        }
    ]
)

# 3. Gold Table: graph_nodes (Applications, Component-Versions, Vulnerabilities)
graph_nodes = pd.DataFrame(
    [
        {"node_id": "app:billing", "node_type": "Application", "label": "Billing"},
        {"node_id": "app:analytics", "node_type": "Application", "label": "Analytics"},
        {"node_id": "comp:billing-helper@1.0.0", "node_type": "ComponentVersion", "label": "billing-helper@1.0.0"},
        {"node_id": "comp:log4j-core@2.14.1", "node_type": "ComponentVersion", "label": "log4j-core@2.14.1"},
        {"node_id": "comp:log4j-core@2.17.1", "node_type": "ComponentVersion", "label": "log4j-core@2.17.1"},
        {"node_id": "vuln:GHSA-jfh8-c2jp-5v3q", "node_type": "Vulnerability", "label": "GHSA-jfh8-c2jp-5v3q"},
    ]
)

# 4. Gold Table: graph_edges (HAS_INVENTORY, DEPENDS_ON, AFFECTED_BY with hashes)
graph_edges = pd.DataFrame(
    [
        # Application -> Root/Direct Component (HAS_INVENTORY)
        {
            "source_id": "app:billing",
            "relation": "HAS_INVENTORY",
            "target_id": "comp:billing-helper@1.0.0",
            "sbom_sha256": BILLING_SBOM_SHA,
            "osv_query_sha256": None,
        },
        {
            "source_id": "app:analytics",
            "relation": "HAS_INVENTORY",
            "target_id": "comp:log4j-core@2.17.1",
            "sbom_sha256": ANALYTICS_SBOM_SHA,
            "osv_query_sha256": None,
        },
        # Transitive Dependency Chain in Billing (DEPENDS_ON)
        {
            "source_id": "comp:billing-helper@1.0.0",
            "relation": "DEPENDS_ON",
            "target_id": "comp:log4j-core@2.14.1",
            "sbom_sha256": BILLING_SBOM_SHA,
            "osv_query_sha256": None,
        },
        # Vulnerability Match carrying both SBOM and OSV-query hashes (AFFECTED_BY)
        {
            "source_id": "comp:log4j-core@2.14.1",
            "relation": "AFFECTED_BY",
            "target_id": "vuln:GHSA-jfh8-c2jp-5v3q",
            "sbom_sha256": BILLING_SBOM_SHA,
            "osv_query_sha256": OSV_QUERY_SHA,
        },
    ]
)