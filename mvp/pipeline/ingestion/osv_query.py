"""Capture exact-version OSV queries with deduplicated batches and complete page evidence."""
import json
from .http import http
from .providers.osv import QUERY_BATCH_URL
from .storage import json_bytes, snapshot, utc_now

BATCH_SIZE = 100
MAX_PAGES = 100

def capture_batch(data_dir, requests, audit=None):
    """Persist the exact ordered POST body and response, including attempt lineage."""
    payload = {'queries': requests}
    request = snapshot(data_dir, 'osv_batch_requests', json_bytes(payload))
    record = {'request': request, 'started_at': utc_now(), 'http': {}}
    try:
        raw = http(QUERY_BATCH_URL, payload, record['http'])
        response = snapshot(data_dir, 'osv_batch', raw)
        record['response'] = response
        results = json.loads(raw).get('results')
        if not isinstance(results, list) or len(results) != len(requests):
            raise ValueError('OSV batch result count does not match request count')
        record['status'] = 'SUCCESS'
        # Operational fields are excluded from immutable query identity.
        stable = lambda entry: {k: entry[k] for k in ('sha256', 'path', 'bytes')}
        return stable(request), stable(response), results
    except Exception as exc:
        record.update(status='FAILED', error=str(exc))
        raise
    finally:
        record['finished_at'] = utc_now()
        if audit is not None:
            audit.append(record)


def result_ids(result):
    if not isinstance(result, dict) or set(result) - {'vulns', 'next_page_token'}:
        raise ValueError('Unexpected OSV batch result shape')
    vulns = result.get('vulns', [])
    if not isinstance(vulns, list) or any(not isinstance(v, dict) or not isinstance(v.get('id'), str) or not v['id'] for v in vulns):
        raise ValueError('Invalid OSV vulnerability list')
    return {v['id'] for v in vulns}


def capture_queries(data_dir, pending, manifest):
    """Batch distinct requests, then follow any pagination for each request.

    A failed or incomplete query never becomes a successful zero-match result.
    Response descriptors link every page and its positional index to the request.
    """
    grouped = {}
    for row in pending:
        grouped.setdefault(json.dumps(row['request'], sort_keys=True), []).append(row)
    groups = list(grouped.values())
    for start in range(0, len(groups), BATCH_SIZE):
        batch = groups[start:start+BATCH_SIZE]
        requests = [g[0]['request'] for g in batch]
        try:
            req, resp, results = capture_batch(data_dir, requests, manifest.setdefault('batches', []))
        except Exception as exc:
            for group in batch:
                for row in group:
                    manifest['queries'].append(dict(row, status='FAILED', error=str(exc), queried_at=utc_now()))
            continue
        for index, group in enumerate(batch):
            request = requests[index]
            pages = []
            try:
                result = results[index]
                pages = [{'request': req, 'response': resp, 'index': index}]
                ids = result_ids(result)
                seen = set()
                while result.get('next_page_token'):
                    token = result['next_page_token']
                    if not isinstance(token, str) or token in seen or len(pages) >= MAX_PAGES:
                        raise ValueError('Invalid or excessive OSV pagination')
                    seen.add(token)
                    rq, rs, rr = capture_batch(data_dir, [dict(request, page_token=token)], manifest.setdefault('batches', []))
                    pages.append({'request': rq, 'response': rs, 'index': 0})
                    result = rr[0]
                    ids |= result_ids(result)
                evidence = snapshot(data_dir, 'osv_queries', json_bytes({'kind': 'batch_evidence', 'request': request, 'pages': pages}))
                for row in group:
                    manifest['queries'].append(dict(row, status='SUCCESS', evidence=evidence, queried_at=utc_now()))
                manifest['_matched'].update(ids)
            except Exception as exc:
                # Retain any completed pages for investigation, but never use
                # partial results as a completed exact-version assessment.
                evidence = snapshot(data_dir, 'osv_queries', json_bytes({'kind':'incomplete_batch_evidence','request':request,'pages':pages})) if pages else None
                for row in group:
                    manifest['queries'].append(dict(row, status='FAILED', error=str(exc), queried_at=utc_now(), evidence=evidence))
