#!/usr/bin/env python3
"""Idle RSS/PSS snapshots with a test-only group OOM boundary.

Never overcommit the shared L1 without a boundary. Five fully resident 768 MiB
guests cannot safely fit beside the L1 kernel/services in this 4 GiB host.
Record a contained capacity failure instead of risking those services.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
import firecracker as fc
from verify import verify

def meminfo():
    return {key:int(value) for key,value in re.findall(r'^(\w+):\s+(\d+) kB$',
            Path('/proc/meminfo').read_text(),re.M)}
def snapshot(v):
    text=Path(f'/proc/{v.p.pid}/smaps_rollup').read_text()
    values={key:int(value) for key,value in re.findall(r'^(\w+):\s+(\d+) kB$',text,re.M)}
    return {'pid':v.p.pid,'rss_kib':values['Rss'],'pss_kib':values['Pss'],
            'private_dirty_kib':values['Private_Dirty'],'swap_kib':values['Swap'],
            'anon_huge_kib':values['AnonHugePages']}
def group_stats(group):
    return {name:(group/name).read_text().strip() for name in
            ['memory.current','memory.peak','memory.max','memory.swap.max','memory.events']}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['bundle','cache','out']: p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--count',type=int,choices=[1,5],required=True)
    p.add_argument('--memory-backing',choices=['None','Transparent'],required=True)
    a=p.parse_args(); bundle=a.bundle.resolve(); cache=a.cache.resolve(); out=a.out.resolve()
    manifest=verify(bundle); fc.verify_release(cache)
    out.mkdir(parents=True,exist_ok=False)
    (out/'manifest.json').write_bytes((bundle/'manifest.json').read_bytes())
    before=meminfo()
    limit=3*1024**3
    if before['MemAvailable']*1024 < limit+256*1024**2:
        raise RuntimeError('insufficient headroom even for the contained density experiment')
    group=Path('/sys/fs/cgroup')/f'kg-density-{os.getpid()}'
    group.mkdir()
    if not (group/'memory.max').exists():
        group.rmdir()
        raise RuntimeError('root memory controller is not enabled; refuse an unguarded test')
    vms=[]
    result={'case':'fc-jailer-idle-density-768','requested':a.count,
            'huge_pages':a.memory_backing,'manifest_sha256':fc.sha(bundle/'manifest.json'),
            'l1_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'conditions':{'vcpu_count_per_vm':1,'mem_size_mib_per_vm':768,
                'work_disk_per_vm':'private fresh 512 MiB XFS','network_device':False,
                'boot_mode':'production; no tenant workload after first kiln true and DNS readiness',
                'snapshots':1,'warmups':0,'launch_gap_ms':100,'idle_after_all_ready_seconds':5,
                'l1_sessions':1,'cache_drop':False,
                'boundary':'smaps_rollup RSS/PSS sampled after 5 s idle following last KG_READY',
                'group_memory_max_bytes':limit,'group_swap_max_bytes':0,'oom_group':True},
            'host_before_kib':before,'ready':0,'vms':[]}
    try:
        # Root controllers must already be available; never change systemd's
        # controller policy. Move only our VMMs, never shared host services.
        (group/'memory.max').write_text(str(limit))
        (group/'memory.swap.max').write_text('0')
        (group/'memory.oom.group').write_text('1')
        for i in range(a.count):
            time.sleep(.1)
            v=fc.VM(f'density-{os.getpid()}-{i}',bundle,cache,out,memory_backing=a.memory_backing)
            vms.append(v)
            (group/'cgroup.procs').write_text(str(v.p.pid))
        for v in vms:
            v.until(b'KG_READY',timeout=150)
            result['ready']+=1
        time.sleep(5)
        if any(v.p.poll() is not None for v in vms):
            raise RuntimeError('a VMM exited before idle snapshot')
        result['vms']=[snapshot(v) for v in vms]
        result['total_rss_kib']=sum(v['rss_kib'] for v in result['vms'])
        result['total_pss_kib']=sum(v['pss_kib'] for v in result['vms'])
        result['outcome']='idle snapshot complete'
    except Exception as error:
        result['outcome']='capacity or boot failure'
        result['error']=str(error)
        result['partial_vms']=[]
        for v in vms:
            if v.p.poll() is None:
                try: result['partial_vms'].append(snapshot(v))
                except (FileNotFoundError,ProcessLookupError): pass
    finally:
        try:
            result['launched']=len(vms)
            result['group']=group_stats(group)
            result['host_at_snapshot_kib']=meminfo()
        finally:
            for v in vms: v.stop()
            group.rmdir()
            result['host_after_cleanup_kib']=meminfo()
            fc.write(out/'density.json',result)
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
