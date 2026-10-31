import json
from pathlib import Path
import shutil
import subprocess
base=Path('/home/estradafamily.guest/kiln-guest-build')
vmms=[]
for p in Path('/proc').iterdir():
    if not p.name.isdigit(): continue
    try:
        args=(p/'cmdline').read_bytes().split(b'\0')
        if args and Path(args[0].decode()).name=='firecracker-v1.17.0-aarch64':
            vmms.append({'pid':int(p.name),'argv':[a.decode(errors='replace') for a in args if a]})
    except (OSError,UnicodeError): pass
if vmms: raise RuntimeError('a VMM is still live; refuse cleanup')
removed=[]
names=['bundle-first-a','bundle-first-b','bundle-hardening-a','bundle-hardening-b','baseline-1534330',
       'trace-bundle','trace-store-bundle','trace-original','trace-free-off','trace-probe','trace-stores',
       'trace-thp-verified','trace-thp-quiet','trace-repack','trace-kernel-work','work-a','work-b',
       'compare-default','compare-thp','compare-alloc-only','phase-before','phase-after',
       'phase-before-v2','phase-after-v2','results-boot-regression','results-boot-regression-v2']
names += ['density-'+v+'-'+str(n) for v in ['thp','default','old'] for n in [1,5]]
names += ['density-fixed-'+v+'-'+str(n) for v in ['thp','default','old'] for n in [1,5]]
for name in names:
    p=base/name
    if p.exists(): shutil.rmtree(p); removed.append(name)
cache_bytes=sum(p.stat().st_size for p in (base/'cache').rglob('*') if p.is_file())
if cache_bytes>=2*1024**3: raise RuntimeError('cache exceeds 2 GiB')
guards=[str(p) for p in Path('/sys/fs/cgroup').glob('kg-density-*')]
if guards: raise RuntimeError('density cgroup remains: '+str(guards))
tap=subprocess.run(['ip','link','show','kgtest0'],capture_output=True,text=True)
firewall=subprocess.run(['nft','list','table','inet','kiln_guest_test'],capture_output=True,text=True)
if tap.returncode==0 or firewall.returncode==0: raise RuntimeError('test network state remains')
services=subprocess.run(['systemctl','list-units','--all','--no-legend','--plain','kiln*','kilnd*'],capture_output=True,text=True)
result={'cache_bytes':cache_bytes,'cache_under_2_gib':True,'removed':removed,'vmm_processes':vmms,
        'density_cgroups':guards,'test_tap_absent':True,'test_firewall_table_absent':True,
        'kernel_build_trees_absent':all(not (base/n).exists() for n in ['work-a','work-b','trace-kernel-work']),
        'services':services.stdout.strip(),'retained_bundles':['bundle-a','bundle-b']}
print(json.dumps(result,indent=2,sort_keys=True))
