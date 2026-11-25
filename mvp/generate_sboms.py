"""Resolve release tags to immutable commits and generate genuine CycloneDX SBOMs.

Run in an isolated, non-privileged build VM without cloud credentials. Maven can
execute repository-controlled plugins. Only inventory generation is requested;
no historical application is launched. Failed releases never get dummy SBOMs.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from component_identity import inventory
from storage import ROOT, atomic_write, json_bytes, utc_now

PLUGIN = '2.9.1'
GOAL = f'org.cyclonedx:cyclonedx-maven-plugin:{PLUGIN}:makeAggregateBom'


def run(args, cwd=None, timeout=1800):
    """Run trusted executable arguments without shell interpolation."""
    return subprocess.run(args, cwd=cwd, check=True, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True).stdout.strip()


def resolve(repo, tag):
    """Resolve annotated and lightweight tags; reject missing/moved references."""
    ref = f'refs/tags/{tag}'
    lines = run(['git', 'ls-remote', '--tags', repo, ref, ref+'^{}'], timeout=90).splitlines()
    refs = {name: sha for sha, name in (line.split() for line in lines)}
    commit = refs.get(ref+'^{}') or refs.get(ref)
    if not commit or not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError(f'Missing release tag: {repo} {tag}')
    return commit


def generate(app, tag, dest, java, maven, refresh=False):
    """Reuse an existing verified inventory, otherwise generate from a pinned commit."""
    dest.mkdir(parents=True, exist_ok=True)
    bom, sidecar = dest/'bom.json', dest/'bom.provenance.json'
    lock = dest/'revision.json'
    repo = app['repository_url']
    if lock.exists():
        pin = json.loads(lock.read_text())
        if (pin['repository_url'], pin['release_tag']) != (repo, tag):
            raise ValueError('Revision lock does not match registry')
        commit = pin['git_commit']
    else:
        commit = resolve(repo, tag)
        atomic_write(lock, json_bytes({'repository_url': repo, 'release_tag':tag, 'git_commit':commit}))
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('Invalid commit in revision lock')
    if bom.exists() and sidecar.exists() and not refresh:
        from pipeline.ingestion.providers.sbom import provenance
        meta = provenance(bom, bom.read_bytes(), app['application_id'])
        if (meta['git_commit'], meta['release_tag'], meta['repository_url']) != (commit, tag, repo):
            raise ValueError('Cached SBOM does not match revision lock')
        inventory(json.loads(bom.read_bytes()))
        return meta
    checkout = ROOT/'data'/'worktrees'/app['application_id']/tag
    checkout.mkdir(parents=True, exist_ok=True)
    if not (checkout/'.git').exists():
        run(['git','init'], checkout)
        run(['git','remote','add','origin',repo], checkout)
    if run(['git','remote','get-url','origin'],checkout) != repo:
        raise ValueError('Unexpected checkout remote')
    run(['git','fetch','--depth=1','origin',commit],checkout)
    run(['git','checkout','--detach',commit],checkout)
    if run(['git','rev-parse','HEAD'],checkout) != commit:
        raise ValueError('Checkout commit mismatch')
    if run(['git','status','--porcelain','--untracked-files=no'],checkout):
        raise ValueError('Checkout has tracked local modifications')
    commit_at = run(['git','show','-s','--format=%cI','HEAD'],checkout)
    output = checkout/'target'/'bom.json'
    output.unlink(missing_ok=True)
    cmd = ['mvn','-B','-ntp',GOAL,'-DoutputFormat=json','-DskipTests',
           '-DincludeTestScope=false','-DincludeProvidedScope=false','-DincludeSystemScope=false',
           '-DincludeRuntimeScope=true','-DincludeCompileScope=true']
    try:
        log = run(cmd, checkout)
        atomic_write(dest/'maven.log', log.encode())
    except subprocess.CalledProcessError as exc:
        atomic_write(dest/'maven.log', (exc.stdout or '').encode())
        raise
    raw = output.read_bytes()
    root, refs = inventory(json.loads(raw))
    if len(refs) < 2:
        raise ValueError('No dependency components in generated SBOM')
    meta = {'application_id':app['application_id'],'release_tag':tag,'repository_url':repo,
            'git_commit':commit,'commit_at':commit_at,'java_version':java,'maven_version':maven,
            'generator_version':PLUGIN,'generated_at':utc_now(),'sbom_sha256':hashlib.sha256(raw).hexdigest(),
            'component_count':len(refs)-1,'scope':'compile/runtime; excludes test/provided/system',
            'generator_command':cmd}
    atomic_write(bom,raw)
    atomic_write(sidecar,json_bytes(meta))
    return meta


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', action='append', help='Limit generation to selected application IDs')
    parser.add_argument('--release', help='Limit to an exact release tag')
    parser.add_argument('--refresh',action='store_true',help='Regenerate existing pinned inventories')
    args = parser.parse_args()
    java, maven = run(['java','-version']), run(['mvn','-version'])
    if 'Apache Maven' not in maven:
        raise ValueError('Install Apache Maven, not the Python mvn package')
    apps = json.loads((ROOT/'applications.json').read_text())
    for app in apps:
        if not re.fullmatch(r'[A-Za-z0-9_-]+',app['application_id']) or not app['repository_url'].startswith('https://github.com/'):
            raise ValueError('Invalid application registry identity or repository')
        if any(not re.fullmatch(r'[A-Za-z0-9_.-]+',tag) or tag in ('.','..') for tag in app['releases']):
            raise ValueError('Invalid release tag in registry')
    records = []
    for app in apps:
        if args.application and app['application_id'] not in args.application:
            continue
        for tag in app['releases']:
            if args.release and tag != args.release:
                continue
            dest = ROOT/'data'/'inventories'/app['application_id']/tag
            try:
                meta = generate(app,tag,dest,java,maven,args.refresh)
                row = dict(meta,status='SUCCESS')
            except Exception as exc:
                row = {'application_id':app['application_id'],'release_tag':tag,'status':'FAILED','error':str(exc)}
            records.append(row)
            print(row['application_id'],tag,row['status'],row.get('error',''),flush=True)
    if not records:
        parser.error('No matching registry entries')
    atomic_write(ROOT/'data'/'metadata'/'generation'/('run-'+utc_now().replace(':','')+'.json'),json_bytes(records))
    return int(any(r['status']=='FAILED' for r in records))

if __name__ == '__main__':
    raise SystemExit(main())
