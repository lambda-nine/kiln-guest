"""Test-only regression of the reviewed nokaslr/heap-init boot PoCs.

Deliberately bypass the host contract ONLY here, to test init's second boundary.
Never imported by the acceptance launcher.
"""
import json
from pathlib import Path
import sys
import firecracker as fc
from unittest import mock

def main():
    bundle,cache,out=map(Path,sys.argv[1:]); out.mkdir(parents=True,exist_ok=False)
    fc.verify_release(cache)
    for name,suffix in [('kaslr-off',' nokaslr'),('heap-off',' init_on_alloc=0 init_on_free=0')]:
        real_profile=fc.profile
        def altered(manifest,profile_name):
            entry=real_profile(manifest,profile_name)
            entry['firecracker']['boot-source']['boot_args']+=suffix
            return entry
        with mock.patch.object(fc,'profile',side_effect=altered), mock.patch.object(fc,'verify_launch'), mock.patch.object(fc,'verify_jailer_argv'):
            v=fc.VM(name,bundle,cache,out,tests=True,memory_backing='Transparent')
        try:
            v.until(b'KG_FATAL runtime launch contract',timeout=60)
            if b'KG_READY' in v.buf or b'KG_FIRST_COMMAND' in v.buf:
                raise RuntimeError('weakened boot became ready')
            print(name+': refused before tenant work/readiness',flush=True)
        finally: v.stop()

if __name__=='__main__': main()
