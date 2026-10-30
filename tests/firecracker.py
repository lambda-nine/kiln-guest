#!/usr/bin/env python3
"""Sequential jailer integration and 20-boot measurements; no guest broker."""
import argparse
import hashlib
import io
import json
import math
import os
from pathlib import Path
import select
import shutil
import signal
import statistics
import subprocess as sp
import tarfile
import time
import sys
import stat
import re

ROOT=Path(__file__).resolve().parents[1]
PINS=json.loads((ROOT/'config/pins.json').read_text())
sys.path.insert(0,str(ROOT/'scripts'))
from kernel_policy import validate as validate_kernel_policy
from inputs import publish_new_directory
from verify import verify as verify_bundle

def run(argv,**kw): return sp.run(list(map(str,argv)),check=True,**kw)
def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()
def write(path,data): path.write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')

def verify_release(cache, expected_digest=None):
    """Bind each executed VMM byte to the pinned archive, including cache hits."""
    archive=(cache/'firecracker.tgz').read_bytes()
    expected_digest=expected_digest or PINS['firecracker']['sha256']
    if hashlib.sha256(archive).hexdigest() != expected_digest:
        raise ValueError('VMM archive digest mismatch')
    folder='release-v1.17.0-aarch64'
    names={f'{folder}/{name}-v1.17.0-aarch64' for name in ['firecracker','jailer']}
    binaries={}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar:
            name=member.name.removeprefix('./')
            if name not in names: continue
            if not member.isfile() or name in binaries: raise ValueError('invalid VMM archive executable')
            binaries[name]=tar.extractfile(member).read()
    if set(binaries) != names: raise ValueError('missing VMM archive executable')
    release=cache/'release'
    if not os.path.lexists(release):
        def populate(destination):
            (destination/folder).mkdir()
            for name,data in binaries.items():
                (destination/name).write_bytes(data); (destination/name).chmod(0o755)
        publish_new_directory(release,populate)
    for directory in [release,release/folder]:
        if not stat.S_ISDIR(directory.lstat().st_mode): raise ValueError('VMM executable directory is not regular')
    for name,data in binaries.items():
        path=release/name
        if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size != len(data) or sha(path) != hashlib.sha256(data).hexdigest():
            raise ValueError(f'VMM executable differs from pinned archive: {name}')
    return release

class Tap:
    def __init__(self): self.name='kgtest0'; self.created=False; self.table=False; self.old=None
    def __enter__(self):
        if sp.run(['ip','link','show',self.name],stdout=sp.DEVNULL,stderr=sp.DEVNULL).returncode==0:
            raise RuntimeError('test TAP already exists; refuse to borrow it')
        if sp.run(['nft','list','table','inet','kiln_guest_test'],stdout=sp.DEVNULL,stderr=sp.DEVNULL).returncode==0:
            raise RuntimeError('test firewall table already exists')
        if sp.run(['ip','route','show','172.30.99.0/30'],capture_output=True,text=True).stdout:
            raise RuntimeError('test subnet already routed')
        try:
            self.old=Path('/proc/sys/net/ipv4/ip_forward').read_text()
            run(['ip','tuntap','add','dev',self.name,'mode','tap','user','10000']); self.created=True
            run(['ip','addr','add','172.30.99.1/30','dev',self.name])
            run(['ip','link','set',self.name,'up'])
            rules='''table inet kiln_guest_test {
 chain input { type filter hook input priority -50; policy accept;
   iifname "kgtest0" drop
 }
 chain forward { type filter hook forward priority -50; policy accept;
   iifname "kgtest0" meta nfproto != ipv4 drop
   iifname "kgtest0" ip saddr != 172.30.99.2 drop
   iifname "kgtest0" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/3 } drop
   iifname "kgtest0" ip daddr 1.1.1.1 udp dport 53 accept
   iifname "kgtest0" tcp dport 80 accept
   iifname "kgtest0" drop
   oifname "kgtest0" ct state established,related accept
   oifname "kgtest0" drop
 }
 chain nat { type nat hook postrouting priority srcnat; policy accept;
   ip saddr 172.30.99.2 masquerade
 }
}
'''
            run(['nft','-f','-'],input=rules,text=True); self.table=True
            Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
            return self
        except BaseException:
            self.__exit__(None,None,None); raise
    def __exit__(self,*_):
        errors=[]
        try:
            if self.table:
                try: run(['nft','delete','table','inet','kiln_guest_test']); self.table=False
                except Exception as e: errors.append(str(e))
            if self.created:
                try: run(['ip','link','del',self.name]); self.created=False
                except Exception as e: errors.append(str(e))
        finally:
            if self.old is not None: Path('/proc/sys/net/ipv4/ip_forward').write_text(self.old)
        if errors: raise RuntimeError('test network cleanup: '+'; '.join(errors))

class VM:
    def __init__(self,name,bundle,cache,out,tests=False,net=False,memory_backing='None',parent_cgroup=None):
        self.p=None; self.buf=b''; self.observations=[]; self.out=out; self.name=name
        if parent_cgroup is not None:
            if not parent_cgroup.startswith('kg-density-') or Path(parent_cgroup).name!=parent_cgroup:
                raise ValueError('invalid density cgroup name')
            if not (Path('/sys/fs/cgroup')/parent_cgroup/'cgroup.procs').is_file():
                raise ValueError('density cgroup must exist before launch')
        release=cache/'release'
        self.fc=release/'release-v1.17.0-aarch64/firecracker-v1.17.0-aarch64'
        jailer=release/'release-v1.17.0-aarch64/jailer-v1.17.0-aarch64'
        self.base=cache.parent/'test-jails'
        self.jail=self.base/self.fc.name/name
        if self.jail.exists(): raise RuntimeError('existing jail')
        self.root=self.jail/'root'; self.root.mkdir(parents=True)
        try:
            for source,dest in [('Image','kernel'),('rootfs.squashfs','rootfs')]:
                os.link(bundle/source,self.root/dest)
            work=self.root/'work'
            with work.open('wb') as f: f.truncate(512*1024*1024)
            run(['mkfs.xfs','-q','-f',work]); os.chown(work,10000,10000)
            cfg={'boot-source':{'kernel_image_path':'/kernel','boot_args':
                'console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/init loglevel=3'+
                (' kiln.test=1' if tests else '')+(' kiln.net=1' if net else '')},
                'machine-config':{'vcpu_count':1,'mem_size_mib':768,'smt':False,'huge_pages':memory_backing},
                'drives':[{'drive_id':'rootfs','path_on_host':'/rootfs','is_root_device':True,'is_read_only':True},
                          {'drive_id':'work','path_on_host':'/work','is_root_device':False,'is_read_only':False}]}
            if net: cfg['network-interfaces']=[{'iface_id':'eth0','guest_mac':'06:00:ac:1e:63:02','host_dev_name':'kgtest0'}]
            write(self.root/'config.json',cfg)
            write(out/(name+'.config.json'),cfg)
            argv=[jailer,'--id',name,'--exec-file',self.fc,'--uid','10000','--gid','10000',
                  '--cgroup-version','2','--chroot-base-dir',self.base]
            if parent_cgroup is not None: argv+=['--parent-cgroup',parent_cgroup]
            argv+=['--','--api-sock','/api.sock','--config-file','/config.json']
            write(out/(name+'.jailer.json'),list(map(str,argv)))
            self.start=time.monotonic_ns()
            self.p=sp.Popen(list(map(str,argv)),stdout=sp.PIPE,stderr=sp.STDOUT,stdin=sp.DEVNULL)
        except BaseException: self.stop(); raise
    def until(self,marker,timeout=60):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            index=self.buf.find(marker)
            if index >= 0:
                return next(elapsed for end,elapsed in self.observations if end >= index+len(marker))
            if select.select([self.p.stdout],[],[],.1)[0]:
                chunk=os.read(self.p.stdout.fileno(),65536); self.buf+=chunk
                elapsed=time.monotonic_ns()-self.start
                if chunk: self.observations.append((len(self.buf),elapsed))
                (self.out/(self.name+'.console.log')).write_bytes(self.buf)
                if marker in self.buf:
                    return next(value for end,value in self.observations if end >= self.buf.index(marker)+len(marker))
                if not chunk: break
        raise RuntimeError(f'{self.name} missing {marker!r}:\n'+self.buf.decode(errors='replace'))
    def stop(self):
        if self.p:
            if self.p.poll() is None: self.p.kill()
            self.p.wait(timeout=10)
            self.buf+=self.p.stdout.read(); self.p.stdout.close()
        (self.out/(self.name+'.console.log')).write_bytes(self.buf)
        write(self.out/(self.name+'.observations.json'),self.observations)
        shutil.rmtree(self.jail,ignore_errors=True)
        # Jailer creates only this per-VM cgroup, never remove a parent's group.
        for path in Path('/sys/fs/cgroup').glob(f'**/{self.fc.name}/{self.name}'):
            try: path.rmdir()
            except OSError: pass

    def host_stats(self):
        """Sample after timing; process totals, not guest page-fault counters."""
        status=Path(f'/proc/{self.p.pid}/stat').read_text().rsplit(')',1)[1].split()
        rollup=Path(f'/proc/{self.p.pid}/smaps_rollup').read_text()
        return {'vmm_minor_faults':int(status[7]), 'vmm_major_faults':int(status[9]),
                'vmm_user_ticks':int(status[11]), 'vmm_system_ticks':int(status[12]),
                'vmm_anon_huge_kib':int(re.search(r'^AnonHugePages:\s+(\d+)',rollup,re.M)[1])}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['bundle','cache','out']: p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--runs',type=int,default=20); p.add_argument('--skip-network',action='store_true')
    a=p.parse_args(); bundle=a.bundle.resolve(); cache=a.cache.resolve(); out=a.out.resolve()
    out.mkdir(parents=True,exist_ok=False)
    manifest=verify_bundle(bundle)
    memory_backing=manifest.get('launch_profile',{}).get('huge_pages','None')
    validate_kernel_policy(bundle/'kernel.config')
    if manifest['schema']!=1: raise ValueError('unknown manifest schema')
    for name,entry in manifest['artifacts'].items():
        if Path(name).name!=name or sha(bundle/name)!=entry['sha256'] or (bundle/name).stat().st_size!=entry['bytes']:
            raise ValueError(f'bundle artifact mismatch: {name}')
    release=verify_release(cache)
    before={str(f):sha(f) for f in [Path('/usr/local/bin/kiln'),Path('/usr/local/bin/kilnd')] if f.exists()}
    conditions={'case':'fc-jailer-kiln-none-768','tier':'strong-isolation','workload':['kiln','run','--','true'],
        'gap_ms':100,'warmups':2,'runs':a.runs,'l1_sessions':1,'l1_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'uname':list(os.uname()),'vcpu_count':1,'mem_size_mib':768,'rootfs':'squashfs, read-only',
        'work_disk':'private 512 MiB XFS, nosuid,nodev,noexec,prjquota','uid_gid':10000,'cgroup_version':2,
        'default_seccomp':True,'outer_cgroup_limits':False,'new_pid_namespace':False,
        'cache_drop':False,'timing':'before Popen(jailer) to serial KG_FIRST_COMMAND after first kiln true exits; staging and teardown excluded',
        'manifest_sha256':sha(bundle/'manifest.json'),'host_services':'installed kiln/kilnd/DNS/metrics left active; other host applications uncontrolled',
        'huge_pages':memory_backing,
        'host_thp':{name:Path('/sys/kernel/mm/transparent_hugepage/'+name).read_text().strip()
                    for name in ['enabled','defrag']}}
    (out/'manifest.json').write_bytes((bundle/'manifest.json').read_bytes())
    write(out/'conditions.json',conditions)
    records=[]; result={'integration':{},'egress':'untested'}
    try:
        for mode in ['offline','network']:
            if mode=='network' and a.skip_network: continue
            tap=Tap() if mode=='network' else None
            try:
                if tap: tap.__enter__()
                v=VM('integration-'+mode,bundle,cache,out,tests=True,net=bool(tap),memory_backing=memory_backing)
                try:
                    v.until(b'KG_TESTS_COMPLETE',timeout=150)
                    if b' FAIL' in v.buf or b'KG_FATAL' in v.buf: raise RuntimeError('guest test failure')
                    for name in ['kexec-load-absent','kexec-file-absent','bpf-syscall-absent',
                                 'io-uring-absent','userfaultfd-absent','perf-events-absent',
                                 'modules-absent','proc-kcore-absent','devmem-absent',
                                 'devkmem-absent','debugfs-absent','lockdown-confidentiality',
                                 'dns-nonroot','dns-only-bind-capability','dns-no-new-privileges',
                                 'dns-seccomp','dns-root-denied','dns-namespace-denied',
                                 'dns-netlink-denied','dns-policy-readonly','dns-tenant-storage-hidden',
                                 'work-disk-flags','work-direct-exec-denied','overlay-workspace-exec',
                                 'kaslr-enabled','memory-initialization']:
                        if f'KG_TEST {name} PASS'.encode() not in v.buf:
                            raise RuntimeError(f'missing security assertion: {name}')
                    v.until(b'Firecracker exiting successfully',timeout=20)
                    if v.p.wait(timeout=5)!=0: raise RuntimeError('guest shutdown failed')
                    result['integration'][mode]='passed'
                    if tap: result['egress']='passed: test-only TAP/NAT, DNS 1.1.1.1 and public TCP/80'
                finally: v.stop()
            except Exception as e:
                result['integration'][mode]={'error':str(e)}
                write(out/'test-results.json',result)
                raise
            finally:
                if tap: tap.__exit__(None,None,None)
        for i in range(a.runs+2):
            time.sleep(.1)
            v=VM(f'boot-{i:02}',bundle,cache,out,memory_backing=memory_backing)
            try:
                elapsed=v.until(b'KG_FIRST_COMMAND')
                v.until(b'KG_READY')
                record={'schema':1,'kind':'latency','case':conditions['case'],'session':conditions['l1_boot_id'],
                    'warmup':i<2,'round':i-2,'gap_ms':100,'elapsed_ns':elapsed,'ok':True,
                    'host_stats':v.host_stats()}
                records.append(record)
                with (out/'records.jsonl').open('a') as f: f.write(json.dumps(record,sort_keys=True)+'\n')
            finally: v.stop()
        values=sorted(r['elapsed_ns']/1e6 for r in records if not r['warmup'])
        result['latency_ms']={'n':len(values),'p50':statistics.median(values),'p95_nearest_rank':values[math.ceil(.95*len(values))-1],
            'min':min(values),'max':max(values),'failures':0}
    finally:
        after={path:sha(Path(path)) for path in before}
        result['installed_binaries_unchanged']=before==after
        result['installed_binaries_sha256']=after
        write(out/'test-results.json',result)
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
