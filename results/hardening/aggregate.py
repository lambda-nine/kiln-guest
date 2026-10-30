#!/usr/bin/env python3
"""Recompute the hardening acceptance evidence from retained raw artifacts."""
import filecmp
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from inputs import inventory_digest, source_inventory
from kernel_policy import validate

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def load(path): return json.loads(path.read_text())

def main():
    evidence=ROOT/'results/hardening'; run=evidence/'validation'
    a,b=[ROOT/'dist'/name for name in ['bundle-a','bundle-b']]
    ma,mb=[load(path/'manifest.json') for path in [a,b]]
    if ma != mb or not filecmp.cmp(a/'manifest.json',b/'manifest.json',shallow=False):
        raise ValueError('manifest mismatch')
    artifacts={}
    for name,record in ma['artifacts'].items():
        if not filecmp.cmp(a/name,b/name,shallow=False): raise ValueError('artifact bytes differ: '+name)
        for bundle in [a,b]:
            if sha(bundle/name)!=record['sha256'] or (bundle/name).stat().st_size!=record['bytes']:
                raise ValueError('artifact differs from manifest: '+name)
        artifacts[name]={**record,'bytes_equal':True}
    source=inventory_digest(source_inventory(ROOT))
    if source!=ma['inputs']['source']['digest']: raise ValueError('current source differs from built source')
    policy=validate(a/'kernel.config')
    conditions=load(run/'conditions.json'); tests=load(run/'test-results.json')
    if tests['integration']!={'offline':'passed','network':'passed'} or not tests['installed_binaries_unchanged']:
        raise ValueError('integration or installed-binary check failed')
    for mode in ['offline','network']:
        log=(run/f'integration-{mode}.console.log').read_text()
        for check in ['kaslr-enabled','kexec-load-absent','kexec-file-absent','dns-nonroot',
                      'dns-only-bind-capability','dns-no-new-privileges','dns-seccomp',
                      'work-direct-exec-denied','work-disk-flags','overlay-workspace-exec']:
            if f'KG_TEST {check} PASS' not in log: raise ValueError('missing runtime proof: '+check)
        if 'KG_TESTS_COMPLETE' not in log or ' FAIL' in log or 'KG_FATAL' in log:
            raise ValueError('incomplete or failed integration: '+mode)
    records=[json.loads(line) for line in (run/'records.jsonl').read_text().splitlines()]
    if len(records)!=22 or sum(r['warmup'] for r in records)!=2:
        raise ValueError('wrong sample count')
    for i,r in enumerate(records):
        if not r['ok'] or r['warmup']!=(i<2) or r['round']!=i-2 or r['gap_ms']!=100 or r['case']!=conditions['case'] or r['session']!=conditions['l1_boot_id']:
            raise ValueError('record conditions differ')
        log=(run/f'boot-{i:02}.console.log').read_text()
        if 'KG_FIRST_COMMAND' not in log or 'KG_READY' not in log or 'KG_FATAL' in log:
            raise ValueError('failed measured boot')
    if conditions['warmups']!=2 or conditions['runs']!=20 or conditions['l1_sessions']!=1 or conditions['cache_drop']:
        raise ValueError('wrong measurement conditions')
    values=sorted(r['elapsed_ns']/1e6 for r in records if not r['warmup'])
    timing={'n':20,'p50':statistics.median(values),'p95_nearest_rank':values[math.ceil(.95*len(values))-1],
            'min':min(values),'max':max(values),'failures':0}
    if timing!=tests['latency_ms']: raise ValueError('summary differs from raw records')
    result={'reproducible':True,'manifest_sha256':{'a':sha(a/'manifest.json'),'b':sha(b/'manifest.json')},
            'artifacts':artifacts,'source_inventory_sha256':source,'kernel_policy':policy,
            'integration':tests['integration'],'installed_binaries_unchanged':True,
            'latency_ms':timing,'conditions':conditions,
            'residual_risks':['cold boots only; snapshots disabled','Phase 1b admission, broker, outer cgroups and PID isolation remain unimplemented',
                              'local KASLR seed compatibility replacement must be reviewed on kernel/VMM upgrades',
                              'environment/toolchain lock is not a hermetic build container; nested measurements are not bare-metal production results']}
    (evidence/'acceptance.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__': main()
