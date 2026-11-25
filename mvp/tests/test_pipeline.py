"""Offline regression tests. No GCP credentials or network required."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import build_silver as silver
import fetch_live as fetch
from pipeline.ingestion import osv_query
from load_silver_to_bigquery import transaction_sql
from schema_validation import read_schema_contracts
from storage import atomic_write, json_bytes, read_snapshot, snapshot


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)

    def manifest(self, demo=True):
        return {'format_version': 3, 'mode': 'SYNTHETIC_OFFLINE' if demo else 'LIVE',
                'sboms': [], 'advisories': [], 'queries': [], 'errors': [], '_matched': set()}

    def save(self, manifest, name):
        manifest.pop('_matched', None)
        atomic_write(self.data/'metadata'/'runs'/f'{name}.json', json_bytes(manifest))

    def test_fixture_replay_and_zero_matches(self):
        for n in range(2):
            m = self.manifest(); fetch.demo(self.data, m); self.save(m, str(n))
        frames = silver.main(self.data, demo=True)
        self.assertEqual({k:len(v) for k,v in frames.items()}, {
            'sboms':2,'sbom_components':5,'sbom_dependencies':3,'vulnerabilities':1,
            'affected_packages':1,'affected_version_events':2,'component_queries':3,'component_findings':1})
        self.assertEqual(set(frames['component_queries'].status), {'SUCCESS'})
        self.assertEqual(frames['component_findings'].iloc[0].vulnerability_id, 'CVE-2021-44228')

    def test_latest_failure_removes_old_finding(self):
        m = self.manifest(); fetch.demo(self.data, m); self.save(m, '0')
        q = next(q for q in m['queries'] if q['request']['version']=='2.14.1')
        updated = dict(q, status='FAILED', queried_at='2026-11-25T00:00:00Z', error='timeout')
        updated.pop('evidence')
        self.save(dict(m, queries=[updated], sboms=[], advisories=[]), '1')
        frames = silver.main(self.data, demo=True)
        self.assertEqual(len(frames['component_findings']), 0)
        self.assertIn('FAILED', set(frames['component_queries'].status))

    def test_hash_and_path_validation(self):
        entry = snapshot(self.data, 'osv_batch', b'{}')
        self.assertEqual(snapshot(self.data, 'osv_batch', b'{}')['storage_status'], 'reused')
        (self.data/entry['path']).write_bytes(b'{ }')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            read_snapshot(self.data, entry)
        with self.assertRaisesRegex(ValueError, 'Invalid snapshot path'):
            read_snapshot(self.data, dict(entry, path='../outside.json'))

    def test_batch_pagination_and_stable_evidence(self):
        request = {'package': {'ecosystem':'Maven','name':'a:b'},'version':'1'}
        row = {'request':request,'sbom_sha256':'a','bom_ref':'b','queried_at':'2026-11-24T12:00:00Z'}
        replies = [json_bytes({'results':[{'vulns':[{'id':'A'}],'next_page_token':'token'}]}),
                   json_bytes({'results':[{'vulns':[{'id':'B'}]}]})]
        hashes = []
        for _ in range(2):
            m = self.manifest(False)
            with patch.object(osv_query, 'http', side_effect=replies) as call:
                fetch.capture_queries(self.data, [row], m)
                self.assertEqual(call.call_count, 2)
            entry = m['queries'][0]['evidence']; hashes.append(entry['sha256'])
            self.assertEqual(silver.matched_ids(self.data, entry, request), {'A','B'})
        self.assertEqual(*hashes)

    def test_bad_batch_is_failed_not_no_match(self):
        m = self.manifest(False)
        with patch.object(osv_query, 'http', return_value=b'{"results":[]}'):
            fetch.capture_queries(self.data, [{'request':{'package':{'ecosystem':'Maven','name':'a:b'},'version':'1'}}], m)
        self.assertEqual(m['queries'][0]['status'], 'FAILED')
        self.assertNotIn('evidence', m['queries'][0])

    def test_partial_pagination_never_success(self):
        m = self.manifest(False)
        request = {'package': {'ecosystem':'Maven','name':'a:b'},'version':'1'}
        row = {'request':request,'sbom_sha256':'a','bom_ref':'b'}
        replies = [json_bytes({'results':[{'vulns':[{'id':'A'}],'next_page_token':'token'}]}),TimeoutError('timed out')]
        with patch.object(osv_query, 'http', side_effect=replies):
            fetch.capture_queries(self.data,[row],m)
        q = m['queries'][0]
        self.assertEqual(q['status'],'FAILED')
        self.assertEqual(read_snapshot(self.data,q['evidence'])['kind'],'incomplete_batch_evidence')
        self.assertEqual(m['_matched'],set())
        self.assertEqual([b['status'] for b in m['batches']],['SUCCESS','FAILED'])

    def test_transaction_shape(self):
        contracts = read_schema_contracts(silver.SQL_DIR)
        sql = transaction_sql('p.d', {k:f'p.d.stage_{k}' for k in contracts}, contracts)
        self.assertTrue(sql.startswith('BEGIN TRANSACTION;'))
        self.assertTrue(sql.endswith('COMMIT TRANSACTION;'))
        self.assertEqual(sql.count('MERGE `p.d.'), 8)
        self.assertIn('DELETE FROM `p.d.component_findings`', sql)
        self.assertIn('S.queried_at >= T.queried_at', sql)


if __name__ == '__main__':
    unittest.main()
