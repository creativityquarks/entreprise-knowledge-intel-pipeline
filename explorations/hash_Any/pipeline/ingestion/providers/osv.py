"""OSV source configuration."""

BASE_URL = "https://storage.googleapis.com/cve-osv-conversion/osv-output"
QUERY_URL = "https://api.osv.dev/v1/query"
VULN_API_URL = "https://api.osv.dev/v1/vulns"


def get_url(vulnerability_id: str) -> str:
    return f"{BASE_URL}/{vulnerability_id}.json"


def get_vuln_api_url(vulnerability_id: str) -> str:
    """Resolve any OSV advisory ID (GHSA-*, CVE-*, etc.) via the OSV API."""
    return f"{VULN_API_URL}/{vulnerability_id}"
