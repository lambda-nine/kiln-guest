#!/usr/bin/env python3
"""Verified diagnostic comparisons on a fixed bundle, in explicit test mode.

Support small lock sessions via --start/--count; all samples must share one
L1 boot, artifact identity, and options. Two warmups precede twenty samples.
This is not the production-mode acceptance harness.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
import firecracker as fc
from verify import verify

OPTIONS={'default':('None',''), 'thp':('Transparent',''),
         'alloc-only':('None','init_on_alloc=1 init_on_free=0')}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['bundle','cache','out']: p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--option',choices=OPTIONS,required=True)
    p.add_argument('--start',type=int,default=0); p.add_argument('--count',type=int,default=22)
    a=p.parse_args(); bundle=a.bundle.resolve(); cache=a.cache.resolve(); out=a.out.resolve()
    manifest=verify(bundle); manifest_bytes=(bundle/'manifest.json').read_bytes()
    fc.verify_release(cache)
    backing,overrides=OPTIONS[a.option]
    conditions={'case':'fc-jailer-kiln-none-768','option':a.option,'huge_pages':backing,
        'boot_overrides':overrides,'diagnostic':True,'kiln.test':1,'loglevel':3,
        'vcpu_count':1,'mem_size_mib':768,'work_disk':'private 512 MiB XFS',
        'gap_ms':100,'warmups':2,'runs':20,'l1_sessions':1,'cache_drop':False,
        'l1_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'manifest_sha256':hashlib.sha256(manifest_bytes).hexdigest(),
        'timing':'before Popen(jailer) to serial KG_FIRST_COMMAND after first kiln true exits; staging and teardown excluded',
        'host_thp':{name:Path('/sys/kernel/mm/transparent_hugepage/'+name).read_text().strip()
                    for name in ['enabled','defrag']}}
    out.mkdir(parents=True,exist_ok=True)
    if (out/'conditions.json').exists():
        if json.loads((out/'conditions.json').read_text())!=conditions:
            raise ValueError('comparison conditions changed between lock sessions')
    else:
        fc.write(out/'conditions.json',conditions); (out/'manifest.json').write_bytes(manifest_bytes)
    records=[]
    if (out/'records.jsonl').exists():
        records=[json.loads(s) for s in (out/'records.jsonl').read_text().splitlines()]
    if len(records)!=a.start or not 0<=a.start<a.start+a.count<=22:
        raise ValueError('nonsequential or invalid sample range')
    if any(not r.get('ok') for r in records):
        raise ValueError('failed attempt retained; use a new output directory')
    original_write=fc.write
    def write(path,data):
        if path.name=='config.json': data['boot-source']['boot_args']+=' '+overrides
        original_write(path,data)
    fc.write=write
    try:
        for i in range(a.start,a.start+a.count):
            record={'round':i-2,'warmup':i<2,'ok':False}
            v=None
            try:
                name=f'option-{a.option}-{i:02}'
                if any(out.glob(name+'.*')):
                    raise ValueError('attempt files already exist; refuse to overwrite')
                if verify(bundle)!=manifest: raise ValueError('bundle changed during comparison')
                time.sleep(.1)
                v=fc.VM(name,bundle,cache,out,tests=True,memory_backing=backing)
                record['elapsed_ns']=v.until(b'KG_FIRST_COMMAND',timeout=90)
                v.until(b'KG_READY',timeout=90)
                record['host_stats']=v.host_stats(); record['ok']=True
            except BaseException as error:
                record['error']=str(error); raise
            finally:
                cleanup_error=None
                try:
                    if v is not None: v.stop()
                except Exception as error:
                    record['ok']=False; record['cleanup_error']=str(error); cleanup_error=error
                try:
                    original_write(out/f'observations-{i:02}.json',v.observations if v is not None else [])
                except Exception as error:
                    record['ok']=False; record['observation_error']=str(error); cleanup_error=error
                finally:
                    with (out/'records.jsonl').open('a') as f: f.write(json.dumps(record,sort_keys=True)+'\n')
                if cleanup_error is not None: raise RuntimeError('attempt cleanup/evidence failure') from cleanup_error
            records.append(record)
            print(json.dumps(record),flush=True)
    finally:
        fc.write=original_write
    values=sorted(r['elapsed_ns']/1e6 for r in records if not r['warmup'] and r['ok'])
    if len(records)==22:
        original_write(out/'summary.json',{'conditions':conditions,'latency_ms':{
            'n':len(values),'p50':statistics.median(values),'p95_nearest_rank':values[math.ceil(.95*len(values))-1],
            'min':min(values),'max':max(values),'failures':sum(not r['ok'] for r in records)}})

if __name__=='__main__': main()
