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
            'anon_huge_kib':values['AnonHugePages'],
            'cgroup':Path(f'/proc/{v.p.pid}/cgroup').read_text().strip()}
def group_stats(group):
    return {name:(group/name).read_text().strip() for name in
            ['memory.current','memory.peak','memory.max','memory.swap.max','memory.events']}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['bundle','cache','out']: p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--count',type=int,choices=[1,5],required=True)
    p.add_argument('--memory-backing',choices=['None','Transparent'],required=True)
    p.add_argument('--proof',type=Path,help='verified single-VM density.json required before a five-VM attempt')
    a=p.parse_args(); bundle=a.bundle.resolve(); cache=a.cache.resolve(); out=a.out.resolve()
    manifest=verify(bundle); fc.verify_release(cache)
    if a.count==5:
        if a.proof is None: raise ValueError('five-VM run requires single-VM charging proof')
        proof=json.loads(a.proof.read_text())
        if (proof.get('requested')!=1 or not proof.get('preexec_charge_verified') or
            proof.get('manifest_sha256')!=fc.sha(bundle/'manifest.json') or
            proof.get('huge_pages')!=a.memory_backing):
            raise ValueError('single-VM charging proof does not match this experiment')
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
                'group_memory_max_bytes':limit,'group_swap_max_bytes':0,'oom_group':True,
                'cgroup_placement':'jailer --parent-cgroup before Firecracker exec'},
            'host_before_kib':before,'ready':0,'vms':[]}
    try:
        # Jailer 1.17 joins an existing v2 parent before exec when no --cgroup
        # overrides are supplied. Never migrate an already-running VMM.
        (group/'memory.max').write_text(str(limit))
        (group/'memory.swap.max').write_text('0')
        (group/'memory.oom.group').write_text('1')
        for i in range(a.count):
            time.sleep(.1)
            v=fc.VM(f'density-{os.getpid()}-{i}',bundle,cache,out,
                    memory_backing=a.memory_backing,parent_cgroup=group.name)
            vms.append(v)
        for v in vms:
            v.until(b'KG_READY',timeout=150)
            result['ready']+=1
        time.sleep(5)
        if any(v.p.poll() is not None for v in vms):
            raise RuntimeError('a VMM exited before idle snapshot')
        result['vms']=[snapshot(v) for v in vms]
        if any(row['cgroup']!='0::/'+group.name for row in result['vms']):
            raise RuntimeError('VMM is outside the preconfigured density cgroup')
        charged=int((group/'memory.current').read_text())
        private=sum(row['private_dirty_kib'] for row in result['vms'])*1024
        result['charged_bytes_at_idle']=charged
        if charged < private*.95:
            raise RuntimeError('private resident RAM is not charged to the density group')
        result['preexec_charge_verified']=True
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
            if (group/'cgroup.procs').read_text().strip(): (group/'cgroup.kill').write_text('1')
            errors=[]
            for v in vms:
                try: v.stop()
                except Exception as error: errors.append(str(error))
            try: group.rmdir()
            except OSError as error: errors.append(str(error))
            if errors: result['cleanup_errors']=errors
            result['host_after_cleanup_kib']=meminfo()
            fc.write(out/'density.json',result)
            if errors: raise RuntimeError('density cleanup failed: '+'; '.join(errors))
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
