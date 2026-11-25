"""Execute the translated Gold logic on SQLite using the original fixture.

Only dialect-only casts/UNION DISTINCT and dbt relation macros are adapted for
this local test. BigQuery compilation and execution still require dbt/ADC.
"""
import json
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
import pandas as pd
from build_gold import shortest_paths
from build_silver import main as build_silver
from pipeline.ingestion.ingest import demo
from pipeline.ingestion.storage import atomic_write,json_bytes
from pipeline.ingestion import http as transport
from unittest.mock import patch
from urllib.error import HTTPError
from component_identity import maven_request
from generate_sboms import resolve
from config import ROOT

ORDER=['int_current_sboms','int_component_paths','mart_application_findings','mart_application_overview','graph_nodes','graph_edges']

def render(sql):
    sql=re.sub(r"\{\{\s*source\('[^']+','([^']+)'\)\s*\}\}",r'\1',sql)
    sql=re.sub(r"\{\{\s*ref\('([^']+)'\)\s*\}\}",r'\1',sql)
    return sql.replace('UNION DISTINCT','UNION')

class GoldTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        path=Path(self.temp.name)
        m={'format_version':3,'mode':'SYNTHETIC_OFFLINE','sboms':[],'advisories':[],'queries':[],'errors':[],'_matched':set()}
        demo(path,m)
        atomic_write(path/'metadata'/'runs'/'fixture.json',json_bytes(m))
        self.frames=build_silver(path,demo=True)
        self.con=sqlite3.connect(':memory:'); self.addCleanup(self.con.close)

    def publish(self):
        for name,frame in self.frames.items():
            frame=frame.copy()
            for col in frame.columns:
                if any(isinstance(x,list) for x in frame[col]):
                    frame[col]=frame[col].map(json.dumps)
                if str(frame[col].dtype).startswith('datetime'):
                    frame[col]=frame[col].astype('string')
            frame.to_sql(name,self.con,if_exists='replace',index=False)
        rows=[]
        for s in self.frames['sboms'].itertuples():
            cs=self.frames['sbom_components']; ds=self.frames['sbom_dependencies']
            names=dict(zip(cs.loc[cs.source_sha256==s.source_sha256,'bom_ref'],cs.loc[cs.source_sha256==s.source_sha256,'name']))
            edges=list(ds.loc[ds.source_sha256==s.source_sha256,['parent_bom_ref','child_bom_ref']].itertuples(index=False,name=None))
            rows.extend(shortest_paths(s.source_sha256,s.root_component_ref,names,edges))
        pd.DataFrame(rows).to_sql('component_paths',self.con,if_exists='replace',index=False)
        for name in ORDER:
            self.con.execute('DROP TABLE IF EXISTS '+name)
            self.con.execute('CREATE TABLE '+name+' AS '+render((ROOT/'gold'/'models'/(name+'.sql')).read_text()))
        for file in (ROOT/'gold'/'tests').glob('*.sql'):
            self.assertEqual(self.con.execute(render(file.read_text())).fetchall(),[],file.name)

    def test_gold_matches_reference(self):
        self.publish()
        self.assertEqual(self.con.execute('SELECT COUNT(*) FROM mart_application_overview').fetchone()[0],2)
        self.assertEqual(self.con.execute('SELECT COUNT(*) FROM mart_application_findings').fetchone()[0],1)
        self.assertEqual(self.con.execute('SELECT COUNT(*) FROM graph_nodes').fetchone()[0],8)
        self.assertEqual(self.con.execute('SELECT COUNT(*) FROM graph_edges').fetchone()[0],6)
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM mart_application_overview WHERE risk_flag='NO_MATCH_IN_QUERIED_OSV'").fetchone()[0],1)
        self.publish() # replace derived results on replay
        self.assertEqual(self.con.execute('SELECT COUNT(*) FROM mart_application_findings').fetchone()[0],1)

    def test_failed_query_never_clear(self):
        q=self.frames['component_queries']; idx=q.index[q.component_version=='2.14.1'][0]
        sha=q.loc[idx,'source_sha256']; q.loc[idx,'status']='FAILED'
        self.frames['component_findings']=self.frames['component_findings'].iloc[0:0]
        self.publish()
        self.assertEqual(self.con.execute('SELECT risk_flag FROM mart_application_overview WHERE inventory_snapshot_sha256=?',(sha,)).fetchone()[0],'QUERY_INCOMPLETE')

    def test_missing_or_skipped_query_never_clear(self):
        q=self.frames['component_queries']
        idx=q.index[q.component_version=='2.14.1'][0]
        sha=q.loc[idx,'source_sha256']
        self.frames['component_findings']=self.frames['component_findings'].iloc[0:0]
        for scenario in ('SKIPPED','MISSING'):
            self.frames['component_queries']=q.copy()
            if scenario=='SKIPPED': self.frames['component_queries'].loc[idx,'status']='SKIPPED'
            else: self.frames['component_queries']=q.drop(idx)
            self.publish()
            self.assertEqual(self.con.execute('SELECT risk_flag FROM mart_application_overview WHERE inventory_snapshot_sha256=?',(sha,)).fetchone()[0],'QUERY_INCOMPLETE')

    def test_multiple_releases_same_app(self):
        s=self.frames['sboms']; old=s.iloc[0].source_sha256; new='e'*64
        self.frames['sboms'].loc[0,'release_tag']='v1'
        for name in ['sboms','sbom_components','sbom_dependencies','component_queries','component_findings']:
            frame=self.frames[name]; copy=frame[frame.source_sha256==old].copy(); copy['source_sha256']=new
            if name=='sboms': copy['release_tag']='v2'
            self.frames[name]=pd.concat([frame,copy],ignore_index=True)
        self.publish()
        self.assertEqual(self.con.execute('SELECT COUNT(*) FROM mart_application_overview').fetchone()[0],3)

    def test_cycle_shortest_path(self):
        paths=shortest_paths('s','a',{c:c for c in 'abcd'},[('a','b'),('a','c'),('b','d'),('c','d'),('d','a')])
        self.assertEqual(len(paths),4)
        self.assertEqual(paths[-1]['path_text'],'a > b > d')

    def test_retry_and_identity(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self,n): return b'{}'
        err=HTTPError('https://example.org',429,'rate limit',{'Retry-After':'1'},None)
        with patch.object(transport.urllib.request,'urlopen',side_effect=[err,Response()]) as call, patch.object(transport.time,'sleep') as sleep:
            self.assertEqual(transport.http('https://example.org'),b'{}'); self.assertEqual(call.call_count,2); sleep.assert_called_once_with(1)
        comp={'group':'a','name':'b','version':'1','purl':'pkg:maven/a/b@1?type=jar'}
        self.assertEqual(maven_request(comp)['package']['name'],'a:b')
        self.assertIsNone(maven_request(dict(comp,purl='pkg:maven/a/b@1?classifier=sources')))

    def test_tag_resolution(self):
        with patch('generate_sboms.run',return_value='a'*40+'\trefs/tags/v1\n'+'b'*40+'\trefs/tags/v1^{}'):
            self.assertEqual(resolve('https://example.org/repo','v1'),'b'*40)

if __name__=='__main__': unittest.main()
