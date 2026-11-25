"""OSV endpoint definitions; transport and retry policy live in http.py."""
from urllib.parse import quote

BASE_URL = 'https://api.osv.dev/v1'
QUERY_BATCH_URL = BASE_URL + '/querybatch'


def get_vuln_api_url(vulnerability_id: str) -> str:
    """Return the full-advisory endpoint for an ID discovered by OSV."""
    return BASE_URL + '/vulns/' + quote(vulnerability_id, safe='')
