"""Send exported nodes and edges to localhost mock API; no external data sharing."""
import json
import sys
import urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
run=int(sys.argv[1]) if len(sys.argv)>1 else 1
output=ROOT/'data'/'outputs'
payload=json.dumps({'nodes':json.loads((output/f'graph_nodes_run{run}.json').read_text()),'edges':json.loads((output/f'graph_edges_run{run}.json').read_text())}).encode()
request=urllib.request.Request('http://127.0.0.1:8765/ingest',data=payload,headers={'Content-Type':'application/json'},method='POST')
with urllib.request.urlopen(request,timeout=5) as response:print('INGEST:',response.read().decode())
with urllib.request.urlopen('http://127.0.0.1:8765/path',timeout=5) as response:print('PATH:',response.read().decode())
