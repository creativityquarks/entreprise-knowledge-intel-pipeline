"""OSV source configuration."""

BASE_URL = "https://storage.googleapis.com/cve-osv-conversion/osv-output"


def get_url(vulnerability_id: str) -> str:
    return f"{BASE_URL}/{vulnerability_id}.json"
