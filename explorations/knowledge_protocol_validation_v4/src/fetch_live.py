"""Explicit opt-in network probe; no silently substituted offline fixtures."""
import hashlib
import json
import urllib.request
from pathlib import Path
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parents[1]
DEST=ROOT/'data'/'raw'
SOURCES={
 'osv_log4shell':'https://storage.googleapis.com/cve-osv-conversion/osv-output/CVE-2021-44228.json',
 'github_log4shell':'https://api.github.com/advisories/GHSA-jfh8-c2jp-5v3q',
 'github_advisories_page1':'https://api.github.com/advisories?per_page=5&page=1',
 'cisa_kev':'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
 'cyclonedx_dependencies':'https://raw.githubusercontent.com/CycloneDX/bom-examples/master/CBOM/Example-With-Dependencies/bom.json',
}
def main():
    DEST.mkdir(parents=True,exist_ok=True)
    results=[]
    for name,url in SOURCES.items():
        record={'name':name,'url':url,'retrieved_utc':datetime.now(timezone.utc).isoformat()}
        try:
            req=urllib.request.Request(url,headers={'User-Agent':'knowledge-protocol-feasibility/0.1','Accept':'application/json'})
            with urllib.request.urlopen(req,timeout=25) as resp:
                raw=resp.read(12_000_001)
                if len(raw)>12_000_000: raise ValueError('Size cap exceeded (12 MB)')
                obj=json.loads(raw)
                record.update({'status':'downloaded','status_code':resp.status,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'etag':resp.headers.get('ETag'),'last_modified':resp.headers.get('Last-Modified'),'top_level_keys':list(obj)[:30] if isinstance(obj,dict) else ['ARRAY'],'link_header':resp.headers.get('Link')})
                (DEST/f'{name}.json').write_bytes(raw)
        except Exception as e:
            record.update({'status':'failed','error':f'{type(e).__name__}: {e}'})
        results.append(record)
        print(record['name'],record['status'])
    (DEST/'live_manifest.json').write_text(json.dumps(results,indent=2)+'\n')
    print('Manifest:',DEST/'live_manifest.json')
if __name__=='__main__':main()
