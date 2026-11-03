#!/usr/bin/env python3
"""Linux/aarch64 builder. Run prepare once, then build in two clean directories."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess as sp
import sys
import tarfile
import urllib.request
from inputs import cargo_arguments, cargo_environment, publish_new_directory, sha, vendor_crates, verify_source
from kernel_policy import validate as validate_kernel_policy
from launch_contract import contract, CMDLINE, FC_SUFFIX, PHASE1B_PROFILE
from phase1b_contract import refuse_build
from build_environment import FIXED_PATH

ROOT = Path(__file__).resolve().parents[1]
PINS = json.loads((ROOT / 'config/pins.json').read_text())
EPOCH = str(PINS['source_date_epoch'])
TARGET = 'aarch64-unknown-linux-gnu'
PROFILE = 'release'
BROKER_CRATE = 'kilnd-guest-broker'
BROKER_PROTOCOL = 1
BROKER_PORT = 5252
# Source crates of the broker binary, inventoried file by file in the manifest.
BROKER_SOURCES = ('crates/kilnd-guest-broker', 'crates/kilnd-broker-protocol', 'crates/kilnd-exec-core')
# Both reviewed source archives follow their pins.json digest into build-lock.json.
SOURCE_LOCK_KEYS = ('kiln_source_sha256', 'kilnd_source_sha256')

def run(argv, **kwargs):
    print('+', ' '.join(map(str, argv)), flush=True)
    return sp.run(list(map(str, argv)), check=True, **kwargs)

def output(argv): return sp.check_output(list(map(str, argv)), text=True).strip()
def writejson(path, obj): path.write_text(json.dumps(obj, sort_keys=True, indent=2) + '\n')

def fetch(url, dest, digest):
    if not dest.exists():
        tmp = dest.with_suffix(dest.suffix + '.partial')
        run(['curl', '--proto', '=https', '--tlsv1.2', '-fLsS', '--retry', '2', url, '-o', tmp])
        if sha(tmp) != digest: raise ValueError(f'checksum mismatch: {url}')
        tmp.rename(dest)
    if sha(dest) != digest: raise ValueError(f'checksum mismatch: {dest}')

def toolchain():
    if os.environ.get('PATH') != FIXED_PATH:
        raise ValueError('unapproved build PATH')
    if not (os.statvfs('/').f_flag & os.ST_RDONLY):
        raise ValueError('build requires verified read-only toolchain rootfs')
    names = ['dpkg-deb','tar','bash','sh','curl','gpg','gpgv','git','apt-get','apt-cache','dpkg-query','gcc', 'ld', 'as', 'ar', 'objcopy', 'strip', 'readelf', 'make', 'mksquashfs', 'rustc', 'cargo', 'python3']
    tools = {}
    for name in names:
        p = Path(shutil.which(name)).resolve()
        tools[name] = {'path': str(p), 'sha256': sha(p)}
    return {'tools': tools, 'rustc': output(['rustc','-vV']),
            'packages': output(['dpkg-query','-W','-f=${Package}=${Version}\n',
                'gcc','gcc-13','binutils','libc6','libc6-dev','make','flex','bison',
                'libssl-dev','libelf-dev','bc','squashfs-tools','xfsprogs'])}

def reconcile_lock(existing, current, pins):
    """An existing lock follows reviewed kiln and kilnd pins; the toolchain and debs never move
    here. To repin those, delete config/build-lock.json locally and review the regenerated diff."""
    if existing is None: return current
    if {**existing,**{key:current[key] for key in SOURCE_LOCK_KEYS}} != current:
        raise ValueError('prepare would change build-lock.json; review an intentional repin separately')
    for key in SOURCE_LOCK_KEYS:
        if current[key] not in (existing.get(key),pins.get(key)):
            raise ValueError(f"{key.split('_')[0]} source differs from build-lock.json and pins.json")
    return current

def prepare(cache, kiln_repo):
    cache.mkdir(parents=True, exist_ok=True)
    (cache/'gnupg').mkdir(mode=0o700,exist_ok=True)
    os.environ['GNUPGHOME']=str(cache/'gnupg')
    for k, name in [('kernel', 'linux.tar.xz'), ('firecracker', 'firecracker.tgz')]:
        p = PINS[k]; fetch(p['url'], cache/name, p['sha256'])
    fetch(PINS['alpine']['url'],cache/'alpine.tar.gz',PINS['alpine']['sha256'])
    run(['curl','--proto','=https','-fLsS',PINS['alpine']['url']+'.asc','-o',cache/'alpine.tar.gz.asc'])
    key = ROOT/'config/alpine-ncopa.asc'
    fingerprint = output(['gpg','--batch','--show-keys','--with-colons',key])
    if 'fpr:::::::::0482D84022F52DF1C4E7CD43293ACD0907D9495A:' not in fingerprint:
        raise ValueError('Alpine release key mismatch')
    keyring = cache/'alpine-keyring.gpg'
    run(['gpg','--batch','--yes','--dearmor','--output',keyring,key])
    run(['gpgv','--keyring',keyring,cache/'alpine.tar.gz.asc',cache/'alpine.tar.gz'])
    source = cache/'kiln.tar'
    if not source.exists():
        with source.open('wb') as f:
            run(['git','-C',kiln_repo,'archive','--format=tar',PINS['kiln_commit']],stdout=f)
    if 'kiln_source_sha256' in PINS and sha(source) != PINS['kiln_source_sha256']:
        raise ValueError('kiln source archive mismatch')
    # scripts/lima.py stage_kilnd exports the pinned commit; nothing here fetches it.
    kilnd = cache/'kilnd.tar'
    if not kilnd.exists(): raise ValueError('missing kilnd source archive: run lima.py prepare')
    if sha(kilnd) != PINS['kilnd_source_sha256']:
        raise ValueError('kilnd source archive mismatch')
    # Freeze repository-authenticated .debs, without running their maintainer scripts.
    packages = ['nftables','libnftables1','libnftnl11','libmnl0','libedit2',
                'libxtables12','libjansson4','libgmp10','libc6','libtinfo6','libbsd0','libmd0','libgcc-s1']
    debs = []
    for package in packages:
        version = output(['dpkg-query','-W','-f=${Version}',package])
        text = output(['apt-get','--print-uris','download',f'{package}={version}'])
        match = re.search(r"'(https?://[^']+)'\s+(\S+)\s+\d+\s+SHA(?:256|512):[0-9a-f]+", text)
        metadata = output(['apt-cache','show',f'{package}={version}'])
        sums = re.findall(r'^SHA256: ([0-9a-f]{64})$',metadata,re.M)
        if not match or len(set(sums))!=1:
            raise ValueError(f'no unambiguous authenticated apt URI/SHA256 for {package}: {text}')
        url, name = match.groups(); digest=sums[0]
        # Ubuntu apt sources use HTTP; transport over HTTPS in addition to pinned SHA256.
        url = url.replace('http://', 'https://', 1)
        fetch(url, cache/name, digest)
        debs.append({'package':package,'version':version,'url':url,'file':name,'sha256':digest})
    lock = {'schema':1, 'toolchain':toolchain(), 'debs':debs,
            'kiln_source_sha256':sha(source), 'kilnd_source_sha256':sha(kilnd)}
    existing = ROOT/'config/build-lock.json'
    writejson(existing, reconcile_lock(json.loads(existing.read_text()) if existing.exists() else None,
                                       lock, PINS))

def unpack(archive, dest):
    dest.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as t: t.extractall(dest, filter='data')

def kernel_config(src, out, refresh=False):
    if sha(ROOT/'config/firecracker-v1.17.0-aarch64.config') != PINS['kernel_config_sha256']:
        raise ValueError('upstream CI config mismatch')
    target = ROOT/'config/kernel.config'
    shutil.copyfile(target if target.exists() else ROOT/'config/firecracker-v1.17.0-aarch64.config', out/'.config')
    cfg = [src/'scripts/config', '--file', out/'.config']
    if refresh:
        policy=json.loads((ROOT/'config/security-policy.json').read_text())
        for name,value in policy['required'].items():
            if value != 'y': raise ValueError('configure requires a boolean policy')
            run(cfg+['--enable',name])
        for name in policy['forbidden']: run(cfg+['--disable',name])
    if not target.exists():
        for name in (ROOT/'config/required-builtins.txt').read_text().split(): run(cfg+['--enable',name])
        for name in ['MODULES','DEBUG_INFO','DEBUG_INFO_BTF','DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT',
                     'DEBUG_INFO_DWARF5','GCC_PLUGIN_RANDSTRUCT','LOCALVERSION_AUTO','BPF_PRELOAD']:
            run(cfg+['--disable',name])
        for name, value in [('BUILD_SALT','kiln-guest-1'),('LOCALVERSION','-kiln-guest1'),
                            ('SYSTEM_TRUSTED_KEYS',''),('SYSTEM_REVOCATION_KEYS','')]:
            run(cfg+['--set-str',name,value])
        run(cfg+['--enable','DEBUG_INFO_NONE'])
    run(['make','-C',src,f'O={out}','ARCH=arm64','olddefconfig'])
    text = (out/'.config').read_text()
    validate_kernel_policy(out/'.config')
    for name in (ROOT/'config/required-builtins.txt').read_text().split():
        if f'CONFIG_{name}=y\n' not in text: raise ValueError(f'missing built-in: {name}')
    if re.search(r'^CONFIG_\w+=m$',text,re.M) or 'CONFIG_MODULES=y' in text:
        raise ValueError('modules must be disabled')
    if target.exists() and not refresh and target.read_bytes() != (out/'.config').read_bytes():
        raise ValueError('resolved kernel.config drift')
    if refresh or not target.exists(): shutil.copyfile(out/'.config',target)

def configure(cache, work):
    fetch(PINS['kernel']['url'],cache/'linux.tar.xz',PINS['kernel']['sha256'])
    work.mkdir(parents=True,exist_ok=False)
    try:
        unpack(cache/'linux.tar.xz',work/'linux-source')
        obj=work/'linux-obj'; obj.mkdir()
        kernel_config(work/'linux-source'/f"linux-{PINS['kernel']['version']}",obj,refresh=True)
    finally:
        shutil.rmtree(work)

def copy_elf(source, tree, pool):
    """Read dependency metadata; never execute ldd or downloaded programs."""
    dest = tree / source.relative_to(pool)
    if dest.exists(): return
    if not source.resolve().is_relative_to(pool):
        raise ValueError(f'ELF symlink escapes package tree: {source}')
    dest.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source.resolve(),dest)
    dest.chmod(0o755)
    info = output(['readelf','-l','-d',source])
    interp = re.findall(r'Requesting program interpreter: ([^\]]+)',info)
    needed = re.findall(r'Shared library: \[([^\]]+)\]',info)
    for name in interp+needed:
        if name.startswith('/'):
            candidates = [pool/name.lstrip('/')]
        else:
            candidates = [p for p in pool.rglob(name) if p.is_file()]
        if not candidates: raise ValueError(f'missing dependency {name} for {source}')
        copy_elf(sorted(candidates)[0],tree,pool)

def rustflags(work):
    return f'--remap-path-prefix={work}=/build -C target-feature=+crt-static -C strip=symbols -C link-arg=-Wl,--build-id=none'

def remapped(value, work):
    """What a recorded string looks like after the compiler's own path remap."""
    return value.replace(str(work),'/build')

def require_static(binary, name):
    """A static ELF has no program interpreter for the guest root to supply."""
    info = output(['readelf','-h','-l',binary])
    if 'ELF64' not in info or 'AArch64' not in info or 'INTERP' in info:
        raise ValueError(f'{name} static link failed')

def broker_pin(binary, allow_unpinned):
    """The built broker must equal its pins.json digest and size, except in the explicit
    first pinning build, which reports the values to pin and marks the bundle diagnostic."""
    actual = {'sha256':sha(binary),'bytes':binary.stat().st_size}
    if actual == {'sha256':PINS['broker_sha256'],'bytes':PINS['broker_bytes']}: return actual, True
    if not allow_unpinned:
        raise ValueError(f"built broker differs from pins.json: {actual}; pin it from an --allow-unpinned-broker build")
    banner = '!'*72
    print(f"{banner}\nUNPINNED BROKER (--allow-unpinned-broker): this bundle is diagnostic only.\n"
          f"  broker_sha256 = {actual['sha256']}\n  broker_bytes  = {actual['bytes']}\n"
          f"Review, record these in config/pins.json, then rebuild both bundles.\n{banner}",
          file=sys.stderr, flush=True)
    return actual, False

def build_broker(work, cache, out, allow_unpinned):
    """kilnd's guest broker from the pinned archive, with its own fresh vendor tree."""
    kilnd = work/'kilnd'; unpack(cache/'kilnd.tar',kilnd)
    deps = work/'kilnd-deps'
    cargo = vendor_crates(kilnd,cache,deps)
    flags = rustflags(work)
    argv = ['cargo','build',*cargo_arguments(deps/'vendor'),'-p',BROKER_CRATE,f'--{PROFILE}','--target',TARGET]
    env = cargo_environment(os.environ,deps)
    env.update({'CARGO_INCREMENTAL':'0','CARGO_TARGET_DIR':str(kilnd/'target'),'RUSTFLAGS':flags})
    run(argv,cwd=kilnd,env=env)
    binary = kilnd/'target'/TARGET/PROFILE/BROKER_CRATE
    require_static(binary,'broker')
    shutil.copyfile(binary,out/BROKER_CRATE)
    (out/BROKER_CRATE).chmod(0o755)
    record, pinned = broker_pin(out/BROKER_CRATE,allow_unpinned)
    provenance = kilnd_provenance(cache,kilnd,cargo,{'rustc':output(['rustc','-vV']),
        'rustflags':remapped(flags,work),'cargo_argv':[remapped(a,work) for a in argv],
        'target':TARGET,'profile':PROFILE})
    return record, pinned, provenance

def kilnd_provenance(cache, kilnd, cargo, compiler):
    """Path-free: the archive, its workspace inputs, every broker source file and the compiler."""
    files = []
    for crate in BROKER_SOURCES:
        top = kilnd/crate
        if not top.is_dir() or top.is_symlink(): raise ValueError(f'kilnd archive lacks {crate}')
        for path in sorted(top.rglob('*')):
            if path.is_symlink(): raise ValueError(f'symlink in kilnd source: {path.relative_to(kilnd)}')
            if path.is_file():
                files.append({'path':path.relative_to(kilnd).as_posix(),'sha256':sha(path),'size':path.stat().st_size})
            elif not path.is_dir(): raise ValueError(f'special file in kilnd source: {path.relative_to(kilnd)}')
    return {'commit':PINS['kilnd_commit'],'archive_sha256':sha(cache/'kilnd.tar'),
        'cargo_lock_sha256':sha(kilnd/'Cargo.lock'),'workspace_manifest_sha256':sha(kilnd/'Cargo.toml'),
        'broker_sources':sorted(files,key=lambda record:record['path']),
        'cargo':cargo,'compiler':compiler}

def rootfs(work, cache, out, lock, allow_unpinned_broker=False):
    validate_kiln_source(cache,lock)
    validate_kilnd_source(cache,lock)
    kiln = work/'kiln'; unpack(cache/'kiln.tar',kiln)
    cargo = vendor_crates(kiln,cache,work)
    env = cargo_environment(os.environ,work)
    env.update({'KILN_BUILD_COMMIT':PINS['kiln_commit'], 'CARGO_INCREMENTAL':'0',
        'CARGO_TARGET_DIR':str(kiln/'target'),'RUSTFLAGS':rustflags(work)})
    run(['cargo','build',*cargo_arguments(work/'vendor'),f'--{PROFILE}','--target',TARGET],cwd=kiln,env=env)
    binary = kiln/'target'/TARGET/PROFILE/'kiln'
    require_static(binary,'kiln')
    shutil.copyfile(binary,out/'kiln')
    (out/'kiln').chmod(0o755)
    broker = build_broker(work,cache,out,allow_unpinned_broker)
    tree = work/'root'; tree.mkdir()
    for d in ['dev','proc','sys/fs/cgroup','run','tmp','etc','usr/bin','usr/sbin','usr/local/bin',
              'var/lib/kiln/images/alpine','var/lib/kiln/runs']:
        (tree/d).mkdir(parents=True,exist_ok=True)
    (tree/'usr/lib').mkdir()
    (tree/'lib').symlink_to('usr/lib')
    (work/'launch_cmdline.h').write_text('#define KG_CMDLINE '+json.dumps(CMDLINE)+'\n#define KG_FC_SUFFIX '+json.dumps(FC_SUFFIX)+'\n')
    run(['gcc','-include',work/'launch_cmdline.h','-static','-Os','-Wall','-Wextra','-Werror','-fstack-protector-strong',
         '-D_FORTIFY_SOURCE=2',f'-ffile-prefix-map={ROOT}=/src',
         '-Wl,--build-id=none','-o',tree/'init',ROOT/'src/init.c'])
    run(['strip','--strip-all',tree/'init'])
    # One copy of each: kiln where the design pins it, beside the broker that runs it.
    for name in ['kiln',BROKER_CRATE]:
        shutil.copyfile(out/name,tree/'usr/local/bin'/name); (tree/'usr/local/bin'/name).chmod(0o755)
    pool = work/'deb-root'; pool.mkdir()
    (pool/'usr/lib').mkdir(parents=True)
    (pool/'lib').symlink_to('usr/lib')
    for p in lock['debs']:
        fetch(p['url'],cache/p['file'],p['sha256'])
        run(['dpkg-deb','-x',cache/p['file'],pool])
    nft = pool/'usr/sbin/nft'
    copy_elf(nft,tree,pool)
    # Copy only nft and its transitive libraries; no shell, package manager or xfs tools.
    (tree/'etc/resolv.conf').write_text('nameserver 1.1.1.1\noptions timeout:2 attempts:2\n')
    (tree/'etc/nsswitch.conf').write_text('hosts: files dns\n')
    (tree/'etc/hosts').write_text('127.0.0.1 localhost\n')
    alpine = cache/'alpine.tar.gz'
    fetch(PINS['alpine']['url'],alpine,PINS['alpine']['sha256'])
    image = tree/'var/lib/kiln/images/alpine'
    # Numeric ownership, symlinks and modes survive extraction and squashfs packing.
    # The pinned signed minirootfs has only IDs in kiln's 16-bit namespace.
    with tarfile.open(alpine) as t:
        members=t.getmembers()
        links={m.name.removeprefix('./').rstrip('/') for m in members if m.issym() or m.islnk()}
        for member in members:
            if not 0 <= member.uid < 65536 or not 0 <= member.gid < 65536:
                raise ValueError('Alpine ID outside kiln mapping')
            name=Path(member.name)
            # This pinned minirootfs has zero hard links. Refuse them rather
            # than allow a hard link to alias an absolute symlink's host target.
            if name.is_absolute() or '..' in name.parts or member.isdev() or member.isfifo() or member.islnk():
                raise ValueError('unsafe Alpine archive member')
            if any(str(parent) in links for parent in name.parents if str(parent)!='.'):
                raise ValueError('Alpine member beneath a link')
        t.extractall(image, filter='tar')
    for d in ['sys/fs/cgroup','workspace']: (image/d).mkdir(parents=True,exist_ok=True)
    shifted=set()
    for path in [image]+list(image.rglob('*')):
        key=(path.lstat().st_dev,path.lstat().st_ino)
        if key in shifted: continue
        shifted.add(key)
        st = path.lstat(); os.lchown(path,st.st_uid+2000000000,st.st_gid+2000000000)
        if not path.is_symlink(): os.chmod(path,st.st_mode & 0o7777)
    squash_env=os.environ.copy(); squash_env.pop('SOURCE_DATE_EPOCH',None)
    run(['mksquashfs',tree,out/'rootfs.squashfs','-noappend','-comp','gzip',
         '-processors','1','-no-xattrs','-no-exports','-no-fragments',
         '-all-time',EPOCH,'-mkfs-time',EPOCH,'-no-progress'],env=squash_env)
    return cargo, broker

def input_provenance(cache, lock, source, cargo, kilnd):
    """Everything here is independent of the build's work and output paths."""
    return {'pins_sha256':sha(ROOT/'config/pins.json'),
        'build_lock_sha256':sha(ROOT/'config/build-lock.json'),
        'init_source_sha256':sha(ROOT/'src/init.c'),
        'kiln':{'commit':PINS['kiln_commit'],'archive_sha256':sha(cache/'kiln.tar')},
        'kilnd':kilnd,
        'kernel_archive_sha256':sha(cache/'linux.tar.xz'),
        'kernel_kaslr_patch':PINS['kernel_kaslr_patch'],
        'alpine_archive_sha256':sha(cache/'alpine.tar.gz'),
        'build_lock':lock,'cargo':cargo,'source':source,
        'build_environment':json.loads((ROOT/'config/build-environment.json').read_text()),
        'toolchain_files':json.loads((ROOT/'config/toolchain-files.json').read_text())}

ARTIFACTS = ['Image','kernel.config','kiln',BROKER_CRATE,'rootfs.squashfs']

def assemble(cache, work, out, jobs, lock, source, allow_unpinned_broker=False):
    unpack(cache/'linux.tar.xz',work/'linux-source')
    src = work/'linux-source'/f"linux-{PINS['kernel']['version']}"
    apply_kernel_patch(src)
    obj = work/'linux-obj'; obj.mkdir()
    kernel_config(src,obj)
    run(['make','-C',src,f'O={obj}','ARCH=arm64',f'-j{jobs}',
         f'KCFLAGS=-ffile-prefix-map={work}=/build','Image'])
    shutil.copyfile(obj/'arch/arm64/boot/Image',out/'Image')
    shutil.copyfile(obj/'.config',out/'kernel.config')
    cargo, (broker, pinned, kilnd) = rootfs(work,cache,out,lock,allow_unpinned_broker)
    manifest = {'schema':1,'bundle_version':'0.1.0','architecture':'aarch64',
        'kernel_version':PINS['kernel']['version']+'-kiln-guest1',
        'kiln_commit':PINS['kiln_commit'],'firecracker_version':PINS['firecracker']['version'],
        'source_date_epoch':int(EPOCH),
        'broker':{'enabled':True,'protocol':BROKER_PROTOCOL,'crate':BROKER_CRATE,'port':BROKER_PORT,
                  'kilnd_commit':PINS['kilnd_commit'],**broker},
        'launch_profile':{'huge_pages':'Transparent'},
        'launch_contract':contract(),
        'work_disk':{'filesystem':'xfs','mount_options':['nosuid','nodev','noexec','prjquota'],'minimum_mib':512},
        'artifacts':{name:{'sha256':sha(out/name),'bytes':(out/name).stat().st_size}
            for name in ARTIFACTS},
        'inputs':input_provenance(cache,lock,source,cargo,kilnd)}
    # verify.py refuses diagnostic bundles for acceptance; an unpinned broker is one.
    if not pinned: manifest['diagnostic_only']='unpinned kilnd-guest-broker'
    writejson(out/'manifest.json',manifest)
    if verify_source(ROOT)['digest'] != source['digest']: raise ValueError('source changed during build')
    if not pinned:  # Repeat after the long kernel/squashfs log, where it cannot scroll away.
        print(f"UNPINNED BROKER: broker_sha256={broker['sha256']} broker_bytes={broker['bytes']}",file=sys.stderr,flush=True)

def build(cache, work, out, jobs, source_digest=None, allow_unpinned_broker=False):
    if os.uname().machine != 'aarch64' or os.geteuid() != 0:
        raise ValueError('build requires root on Linux aarch64')
    os.umask(0o022)
    source = verify_source(ROOT)
    if source_digest and source['digest'] != source_digest:
        raise ValueError('staged source differs from the local inventory')
    for name in ['CC','CXX','LD','AR','AS','CFLAGS','CPPFLAGS','LDFLAGS',
                 'KBUILD_OUTPUT','KBUILD_EXTMOD','KCONFIG_CONFIG','MAKEFLAGS']:
        os.environ.pop(name,None)
    lock = json.loads((ROOT/'config/build-lock.json').read_text())
    if toolchain() != lock['toolchain']: raise ValueError('toolchain differs from build lock')
    for key, name in [('kernel','linux.tar.xz'),('firecracker','firecracker.tgz')]:
        fetch(PINS[key]['url'],cache/name,PINS[key]['sha256'])
    validate_kiln_source(cache,lock)
    validate_kilnd_source(cache,lock)
    if os.path.lexists(out): raise ValueError(f'refusing to overwrite {out}')
    work.mkdir(parents=True,exist_ok=False)
    os.environ.update({'SOURCE_DATE_EPOCH':EPOCH,'KBUILD_BUILD_TIMESTAMP':'2026-10-30 00:00:00 UTC',
        'KBUILD_BUILD_USER':'builder','KBUILD_BUILD_HOST':'kiln-guest','KBUILD_BUILD_VERSION':'1',
        'LC_ALL':'C','TZ':'UTC'})
    try:
        publish_new_directory(out,lambda output:assemble(cache,work,output,jobs,lock,source,allow_unpinned_broker))
    finally:
        shutil.rmtree(work)

def validate_kiln_source(cache, lock):
    actual=sha(cache/'kiln.tar')
    if actual != lock['kiln_source_sha256'] or actual != PINS['kiln_source_sha256']:
        raise ValueError('kiln source pin/lock/archive mismatch')

def validate_kilnd_source(cache, lock):
    actual=sha(cache/'kilnd.tar')
    if actual != lock.get('kilnd_source_sha256') or actual != PINS['kilnd_source_sha256']:
        raise ValueError('kilnd source pin/lock/archive mismatch')

def apply_kernel_patch(source):
    patch=PINS['kernel_kaslr_patch']
    original=source/patch['upstream_path']; replacement=ROOT/patch['replacement']
    if sha(original) != patch['upstream_sha256'] or sha(replacement) != patch['sha256']:
        raise ValueError('kernel KASLR source patch digest mismatch')
    shutil.copyfile(replacement,original)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare','build','configure','pin-toolchain'])
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--work',type=Path)
    parser.add_argument('--out',type=Path)
    parser.add_argument('--kiln-repo',type=Path)
    parser.add_argument('--jobs',type=int,default=3)
    parser.add_argument('--source-digest',help='stable inventory digest the staged source must match')
    parser.add_argument('--allow-unpinned-broker',action='store_true',
                        help='first pinning build only: accept a broker that differs from pins.json, '
                             'print its digest and size, and mark the bundle diagnostic')
    parser.add_argument('--profile',choices=['legacy-benchmark',PHASE1B_PROFILE],default='legacy-benchmark',
                        help='manifest schema: 1 for the benchmark bundle; 2 is refused until its artifacts exist')
    args = parser.parse_args()
    if args.profile == PHASE1B_PROFILE: refuse_build()
    for number in [signal.SIGTERM,signal.SIGHUP]: signal.signal(number,lambda *_:sys.exit(143))
    if args.action == 'pin-toolchain':
        path=ROOT/'config/build-lock.json';lock=json.loads(path.read_text());current=toolchain()
        for name,record in lock['toolchain']['tools'].items():
            if record['sha256']!=current['tools'][name]['sha256']:
                raise ValueError('snapshot changed previously pinned tool: '+name)
        lock['toolchain']=current;writejson(path,lock)
    elif args.action == 'prepare': prepare(args.cache.resolve(),args.kiln_repo.resolve())
    elif args.action == 'configure': configure(args.cache.resolve(),args.work.resolve())
    else: build(args.cache.resolve(),args.work.resolve(),args.out.resolve(),args.jobs,args.source_digest,
                args.allow_unpinned_broker)
