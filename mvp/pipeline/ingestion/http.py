"""Bounded HTTP transport for read-only OSV GET and POST requests."""
import json
import time
import urllib.request
from urllib.error import HTTPError, URLError
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from .storage import json_bytes

MAX_BYTES = 12_000_000


def retry_delay(error, attempt):
    """Respect Retry-After within the configured 60-second bound."""
    value = getattr(error, 'headers', {}).get('Retry-After') if getattr(error, 'headers', None) else None
    if value:
        try:
            seconds = float(value)
        except ValueError:
            try:
                seconds = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
            except (ValueError, TypeError):
                seconds = 2 ** attempt
        if seconds > 60:
            raise TimeoutError('Retry-After exceeds configured 60-second retry bound') from error
        return max(0, seconds)
    return min(60, 2 ** attempt)


def http(url, payload=None, metadata=None):
    """Retry transient failures, never retry malformed JSON or permanent 4xx."""
    request = urllib.request.Request(url, data=None if payload is None else json_bytes(payload),
        headers={'User-Agent': 'knowledge-mvp/4', 'Accept': 'application/json',
                 'Content-Type': 'application/json'}, method='GET' if payload is None else 'POST')
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                raw = response.read(MAX_BYTES + 1)
                if metadata is not None:
                    metadata.update(source_url=url, status_code=response.status,
                        content_type=response.headers.get('Content-Type'),
                        etag=response.headers.get('ETag'), last_modified=response.headers.get('Last-Modified'))
            if len(raw) > MAX_BYTES:
                raise ValueError('HTTP response exceeds 12 MB')
            json.loads(raw)
            return raw
        except (HTTPError, URLError, TimeoutError) as exc:
            if isinstance(exc, HTTPError) and exc.code not in (408, 429, 500, 502, 503, 504):
                raise
            if attempt == 3:
                raise
            time.sleep(retry_delay(exc, attempt))
