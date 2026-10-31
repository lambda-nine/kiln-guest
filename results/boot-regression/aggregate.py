#!/usr/bin/env python3
"""Recompute acceptance from retained raw results and byte comparisons."""
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from kernel_policy import validate
from verify import verify

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path): return json.loads(path.read_text())
def stats(records):
    if [r.get('round') for r in records]!=list(range(-2,20)):
        raise ValueError('rounds must be unique and sequential')
    if [r.get('warmup') for r in records]!=[True,True]+[False]*20:
        raise ValueError('incorrect warmup flags')
    rows=[r for r in records if not r['warmup']]
    if len(records)!=22 or len(rows)!=20 or any(not r['ok'] for r in records):
        raise ValueError('require two warmups and twenty successful measured boots')
    values=sorted(r['elapsed_ns']/1e6 for r in rows)
    return {'n':20,'p50':statistics.median(values),'p95_nearest_rank':values[math.ceil(.95*len(values))-1],
            'min':min(values),'max':max(values),'failures':0}
BASE_ARGS='console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/init loglevel=3'.split()

def evidence(directory, manifest_bytes, backing, diagnostic=False, option=None, overrides='', l1=None):
    conditions=read(directory/'conditions.json')
    if (directory/'manifest.json').read_bytes()!=manifest_bytes:
        raise ValueError('archived manifest does not match expected bundle')
    if conditions.get('manifest_sha256')!=hashlib.sha256(manifest_bytes).hexdigest():
        raise ValueError('conditions refer to another manifest')
    if conditions.get('timing')!='before Popen(jailer) to serial KG_FIRST_COMMAND after first kiln true exits; staging and teardown excluded':
        raise ValueError('unexpected timing boundary')
    expected={'case':'fc-jailer-kiln-none-768','gap_ms':100,'warmups':2,'runs':20,
              'l1_sessions':1,'cache_drop':False,'vcpu_count':1,'mem_size_mib':768,'huge_pages':backing}
    if any(conditions.get(k)!=v for k,v in expected.items()):
        raise ValueError('unexpected measurement conditions')
    if l1 is not None and conditions.get('l1_boot_id')!=l1:
        raise ValueError('comparisons do not share an L1 identity')
    if diagnostic:
        if not conditions.get('diagnostic') or conditions.get('kiln.test')!=1 or conditions.get('boot_overrides')!=overrides:
            raise ValueError('incorrect diagnostic option')
    elif conditions.get('diagnostic') or conditions.get('kiln.test') or conditions.get('boot_overrides'):
        raise ValueError('production evidence contains diagnostic overrides')
    records=[json.loads(s) for s in (directory/'records.jsonl').read_text().splitlines()]
    summary=stats(records)
    for i,record in enumerate(records):
        name=f'option-{option}-{i:02}' if diagnostic else f'boot-{i:02}'
        cfg=read(directory/(name+'.config.json'))
        serial=(directory/(name+'.console.log')).read_bytes()
        marker_end=serial.index(b'KG_FIRST_COMMAND')+len(b'KG_FIRST_COMMAND')
        observations=read(directory/(name+'.observations.json'))
        observed=next(ns for end,ns in observations if end>=marker_end)
        if record['elapsed_ns']!=observed:
            raise ValueError('latency record differs from first serial observation')
        args=BASE_ARGS+(['kiln.test=1'] if diagnostic else [])+overrides.split()
        if cfg['boot-source']!={'kernel_image_path':'/kernel','boot_args':cfg['boot-source']['boot_args']}:
            raise ValueError('unexpected boot source')
        if cfg['boot-source']['boot_args'].split()!=args:
            raise ValueError('unexpected production/diagnostic launch arguments')
        if cfg.get('machine-config')!={'vcpu_count':1,'mem_size_mib':768,'smt':False,'huge_pages':backing}:
            raise ValueError('launch profile does not match evidence')
        if set(cfg)!={'boot-source','machine-config','drives'}:
            raise ValueError('unexpected device or launch configuration')
        if cfg['drives']!=[{'drive_id':'rootfs','path_on_host':'/rootfs','is_root_device':True,'is_read_only':True},
                          {'drive_id':'work','path_on_host':'/work','is_root_device':False,'is_read_only':False}]:
            raise ValueError('unexpected disk configuration')
        if not diagnostic and (record.get('session')!=conditions['l1_boot_id'] or record.get('case')!=conditions['case']):
            raise ValueError('record session/case differs from conditions')
    result={'conditions':conditions,'latency_ms':summary}
    result['vmm_anon_huge_kib']=sorted(set(r['host_stats']['vmm_anon_huge_kib'] for r in records if not r['warmup']))
    result['vmm_minor_faults_median']=statistics.median(r['host_stats']['vmm_minor_faults'] for r in records if not r['warmup'])
    return result

def phases(directory):
    trace=read(directory/'trace.json'); data=next(directory.glob('*.console.log')).read_bytes()
    observations=trace['observations']
    def observed(marker):
        index=data.index(marker)
        return next(ns for end,ns in observations if end>=index+len(marker))
    markers=[('start',0),('clear-start',observed(b'clearing system memory')),
             ('slub',observed(b'SLUB:')),('kernel-init',observed(b'Run /init as init process')),
             ('mount-start',observed(b'KG_PHASE mount-work-start')),
             ('mount-done',observed(b'KG_PHASE mount-work-done')),
             ('kiln-start',observed(b'KG_PHASE first-command-start')),
             ('kiln-done',observed(b'KG_PHASE first-command-done')),
             ('first-marker',trace['first_ns']),('ready',trace['ready_ns'])]
    return {'conditions':{k:v for k,v in trace.items() if k!='observations'},
            'boundaries_host_ms':{k:ns/1e6 for k,ns in markers},
            'intervals_ms':{a+' to '+b:(bn-an)/1e6 for (a,an),(b,bn) in zip(markers,markers[1:])}}

def main():
    bundles=[ROOT/'dist'/('bundle-'+name) for name in ['a','b']]
    manifests=[verify(b) for b in bundles]
    if manifests[0]!=manifests[1] or (bundles[0]/'manifest.json').read_bytes()!=(bundles[1]/'manifest.json').read_bytes():
        raise ValueError('independent manifests differ')
    artifacts={}
    for name in manifests[0]['artifacts']:
        equal=(bundles[0]/name).read_bytes()==(bundles[1]/name).read_bytes()
        if not equal: raise ValueError('independent artifact bytes differ: '+name)
        artifacts[name]={**manifests[0]['artifacts'][name],'bytes_equal':equal}
    for label,b in zip(['a','b'],bundles):
        (HERE/f'manifest-{label}.json').write_bytes((b/'manifest.json').read_bytes())
    test=read(HERE/'validation/test-results.json')
    if test['integration']!={'offline':'passed','network':'passed'} or not test['installed_binaries_unchanged']:
        raise ValueError('integration or installed-binary invariant failed')
    original_bytes=(ROOT/'results/hardening/manifest-a.json').read_bytes()
    l1=read(HERE/'compare-default/conditions.json')['l1_boot_id']
    comparisons={option:evidence(HERE/('compare-'+option),original_bytes,backing,True,option,override,l1)
        for option,backing,override in [('default','None',''),('thp','Transparent',''),
                                      ('alloc-only','None','init_on_alloc=1 init_on_free=0')]}
    acceptance=evidence(HERE/'validation',(bundles[0]/'manifest.json').read_bytes(),
                        manifests[0]['launch_profile']['huge_pages'],l1=l1)
    result={'reproducible':True,'artifacts':artifacts,
            'manifest_sha256':{label:sha(b/'manifest.json') for label,b in zip(['a','b'],bundles)},
            'kernel_policy':validate(bundles[0]/'kernel.config'),
            'source_inventory_sha256':manifests[0]['inputs']['source']['digest'],
            'launch_profile':manifests[0]['launch_profile'],
            'comparisons':comparisons,'acceptance':acceptance,
            'integration':test['integration'],'installed_binaries_unchanged':True,
            'installed_binaries_sha256':test['installed_binaries_sha256'],
            'phases':{name:phases(HERE/('phase-'+name)) for name in ['before','after']}}
    (HERE/'acceptance.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({key:result[key] for key in ['reproducible','manifest_sha256','kernel_policy','integration']},indent=2))

if __name__=='__main__': main()
