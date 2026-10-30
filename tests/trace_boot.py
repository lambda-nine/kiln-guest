#!/usr/bin/env python3
"""Single diagnostic boots; never used for acceptance latency measurements.

Run as root under scripts/lima.py's lock. Variants lower defenses ONLY for
causal diagnosis in the explicitly selected fixed guest test mode.
"""
import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import firecracker as fc
from verify import verify as verify_bundle

VARIANTS = {'hardened': '', 'free-off': 'init_on_free=0',
            'alloc-off': 'init_on_alloc=0', 'both-off': 'init_on_free=0 init_on_alloc=0',
            'kaslr-off': 'nokaslr'}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['bundle', 'cache', 'out']:
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--variant', choices=VARIANTS, default='hardened')
    p.add_argument('--initcall-debug', action='store_true')
    p.add_argument('--zero-probe', action='store_true')
    p.add_argument('--memory-backing', choices=['None','Transparent','2M'], default='None')
    p.add_argument('--loglevel', choices=[3,7], type=int, default=7)
    a = p.parse_args()
    a.bundle = a.bundle.resolve(); a.cache = a.cache.resolve(); a.out = a.out.resolve()
    a.out.mkdir(parents=True, exist_ok=False)
    manifest=verify_bundle(a.bundle, allow_diagnostic=True)
    original_manifest=(a.bundle/'manifest.json').read_bytes()
    (a.out/'manifest.json').write_bytes(original_manifest)
    fc.verify_release(a.cache)
    original_write = fc.write
    def write(path, data):
        if path.name == 'config.json':
            data['machine-config']['huge_pages']=a.memory_backing
            data['boot-source']['boot_args'] += f' loglevel={a.loglevel} printk.time=1 '+VARIANTS[a.variant]
            if a.initcall_debug: data['boot-source']['boot_args'] += ' initcall_debug'
            if a.zero_probe: data['boot-source']['boot_args'] += ' kiln.zero_probe=1'
        original_write(path, data)
    fc.write = write
    time.sleep(.1)
    result={'variant':a.variant, 'bundle_verified':True,
            'manifest_sha256':fc.hashlib.sha256(original_manifest).hexdigest(),
            'diagnostic_bundle': 'diagnostic_only' in manifest,
            'l1_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'initcall_debug':a.initcall_debug, 'zero_probe':a.zero_probe}
    result['memory_backing']=a.memory_backing
    result['loglevel']=a.loglevel
    v=None
    try:
        v = fc.VM('trace-'+a.variant, a.bundle, a.cache, a.out, tests=True)
        first = v.until(b'KG_FIRST_COMMAND', timeout=90)
        ready = v.until(b'KG_READY', timeout=90)
        result['host_stats']=v.host_stats()
        result['host_thp']={name:Path('/sys/kernel/mm/transparent_hugepage/'+name).read_text().strip()
                            for name in ['enabled','defrag']}
        result.update({'first_ns': first, 'ready_ns': ready,
                  'conditions': 'diagnostic, 1 boot, 0 warmups, 100 ms idle, 1 L1 session, no cache flush; '+
                  '1 vCPU, 768 MiB, private 512 MiB XFS, jailer; before Popen to serial marker; '+
                  f'kiln.test=1, loglevel={a.loglevel}, printk.time=1',
                  'observations': v.observations})
        print(json.dumps({k:val for k,val in result.items() if k != 'observations'}, indent=2))
    except BaseException as error:
        result['error']=str(error)
        raise
    finally:
        if v is not None: v.stop()
        result['observations']=v.observations if v is not None else []
        original_write(a.out/'trace.json',result)
        fc.write=original_write

if __name__ == '__main__': main()
