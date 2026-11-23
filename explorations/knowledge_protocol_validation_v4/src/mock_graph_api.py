"""Local-only graph API contract simulation, not Neo4j or the VPS API."""
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DB=ROOT/'data'/'outputs'/'mock_graph.sqlite'
SCHEMA='''CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY,type TEXT,label TEXT);
CREATE TABLE IF NOT EXISTS edges(source TEXT,relation TEXT,target TEXT,evidence_sha256 TEXT,PRIMARY KEY(source,relation,target));'''

def ingest(nodes,edges):
    with sqlite3.connect(DB) as conn:
        conn.executescript(SCHEMA)
        ids={n['id'] for n in nodes}
        for e in edges:
            if e['source'] not in ids or e['target'] not in ids or len(e['evidence_sha256'])!=64:
                raise ValueError('Dangling graph edge or missing evidence hash')
        conn.executemany('INSERT OR REPLACE INTO nodes VALUES (?,?,?)',((n['id'],n['type'],n['label']) for n in nodes))
        conn.executemany('INSERT OR REPLACE INTO edges VALUES (?,?,?,?)',((e['source'],e['relation'],e['target'],e['evidence_sha256']) for e in edges))
        return conn.execute('SELECT COUNT(*) FROM nodes').fetchone()[0],conn.execute('SELECT COUNT(*) FROM edges').fetchone()[0]

def reachability(start='app:Billing',target='cve:CVE-2021-44228'):
    with sqlite3.connect(DB) as conn:
        conn.executescript(SCHEMA)
        return conn.execute('''WITH RECURSIVE traverse(node,path,depth) AS (
          SELECT ?, ?, 0 UNION ALL
          SELECT e.target, t.path || ' > ' || e.target, depth+1 FROM traverse t JOIN edges e ON e.source=t.node
          WHERE depth<20 AND instr(t.path,e.target)=0)
          SELECT path FROM traverse WHERE node=? LIMIT 1''',(start,start,target)).fetchone()

class Handler(BaseHTTPRequestHandler):
    def send(self,code,obj):
        raw=json.dumps(obj).encode()
        self.send_response(code); self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    def do_POST(self):
        if self.path!='/ingest':return self.send(404,{'error':'not found'})
        try:
            data=json.loads(self.rfile.read(min(int(self.headers.get('Content-Length','0')),1_000_000)))
            n,e=ingest(data['nodes'],data['edges'])
            self.send(200,{'nodes':n,'edges':e})
        except (ValueError,KeyError,TypeError) as ex:self.send(400,{'error':str(ex)})
    def do_GET(self):
        if self.path!='/path':return self.send(404,{'error':'not found'})
        result=reachability()
        self.send(200,{'reachable':result is not None,'path':result[0] if result else None})
if __name__=='__main__':
    print('Local contract test ONLY, localhost:8765')
    HTTPServer(('127.0.0.1',8765),Handler).serve_forever()
