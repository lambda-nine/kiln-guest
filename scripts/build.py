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

ROOT = Path(__file__).resolve().parents[1]
PINS = json.loads((ROOT / 'config/pins.json').read_text())
EPOCH = str(PINS['source_date_epoch'])

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
    names = ['gcc', 'ld', 'as', 'ar', 'objcopy', 'strip', 'readelf', 'make', 'mksquashfs', 'rustc', 'cargo', 'python3']
    tools = {}
    for name in names:
        p = Path(shutil.which(name)).resolve()
        tools[name] = {'path': str(p), 'sha256': sha(p)}
    return {'tools': tools, 'rustc': output(['rustc','-vV']),
            'packages': output(['dpkg-query','-W','-f=${Package}=${Version}\n',
                'gcc','gcc-13','binutils','libc6','libc6-dev','make','flex','bison',
                'libssl-dev','libelf-dev','bc','squashfs-tools','xfsprogs'])}

def reconcile_lock(existing, current, pinned_source):
    """An existing lock follows a reviewed kiln pin; the toolchain and debs never move here.
    To repin those, delete config/build-lock.json locally and review the regenerated diff."""
    if existing is None: return current
    if {**existing,'kiln_source_sha256':current['kiln_source_sha256']} != current:
        raise ValueError('prepare would change build-lock.json; review an intentional repin separately')
    if current['kiln_source_sha256'] not in (existing['kiln_source_sha256'],pinned_source):
        raise ValueError('kiln source differs from build-lock.json and pins.json')
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
    with source.open('wb') as f:
        run(['git','-C',kiln_repo,'archive','--format=tar',PINS['kiln_commit']],stdout=f)
    if 'kiln_source_sha256' in PINS and sha(source) != PINS['kiln_source_sha256']:
        raise ValueError('kiln source archive mismatch')
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
            'kiln_source_sha256':sha(source)}
    existing = ROOT/'config/build-lock.json'
    writejson(existing, reconcile_lock(json.loads(existing.read_text()) if existing.exists() else None,
                                       lock, PINS.get('kiln_source_sha256')))

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

def rootfs(work, cache, out, lock):
    validate_kiln_source(cache,lock)
    kiln = work/'kiln'; unpack(cache/'kiln.tar',kiln)
    cargo = vendor_crates(kiln,cache,work)
    env = cargo_environment(os.environ,work)
    env.update({'KILN_BUILD_COMMIT':PINS['kiln_commit'], 'CARGO_INCREMENTAL':'0',
        'CARGO_TARGET_DIR':str(kiln/'target'),
        'RUSTFLAGS':f'--remap-path-prefix={work}=/build -C target-feature=+crt-static -C strip=symbols -C link-arg=-Wl,--build-id=none'})
    run(['cargo','build',*cargo_arguments(work/'vendor'),'--release','--target','aarch64-unknown-linux-gnu'],cwd=kiln,env=env)
    binary = kiln/'target/aarch64-unknown-linux-gnu/release/kiln'
    if 'INTERP' in output(['readelf','-l',binary]): raise ValueError('kiln static link failed')
    shutil.copyfile(binary,out/'kiln')
    (out/'kiln').chmod(0o755)
    tree = work/'root'; tree.mkdir()
    for d in ['dev','proc','sys/fs/cgroup','run','tmp','etc','usr/bin','usr/sbin',
              'var/lib/kiln/images/alpine','var/lib/kiln/runs']:
        (tree/d).mkdir(parents=True,exist_ok=True)
    (tree/'usr/lib').mkdir()
    (tree/'lib').symlink_to('usr/lib')
    run(['gcc','-static','-Os','-Wall','-Wextra','-Werror','-fstack-protector-strong',
         '-D_FORTIFY_SOURCE=2',f'-ffile-prefix-map={ROOT}=/src',
         '-Wl,--build-id=none','-o',tree/'init',ROOT/'src/init.c'])
    run(['strip','--strip-all',tree/'init'])
    shutil.copyfile(out/'kiln',tree/'usr/bin/kiln'); (tree/'usr/bin/kiln').chmod(0o755)
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
    return cargo

def input_provenance(cache, lock, source, cargo):
    """Everything here is independent of the build's work and output paths."""
    return {'pins_sha256':sha(ROOT/'config/pins.json'),
        'build_lock_sha256':sha(ROOT/'config/build-lock.json'),
        'init_source_sha256':sha(ROOT/'src/init.c'),
        'kiln':{'commit':PINS['kiln_commit'],'archive_sha256':sha(cache/'kiln.tar')},
        'kernel_archive_sha256':sha(cache/'linux.tar.xz'),
        'kernel_kaslr_patch':PINS['kernel_kaslr_patch'],
        'alpine_archive_sha256':sha(cache/'alpine.tar.gz'),
        'build_lock':lock,'cargo':cargo,'source':source}

def assemble(cache, work, out, jobs, lock, source):
    unpack(cache/'linux.tar.xz',work/'linux-source')
    src = work/'linux-source'/f"linux-{PINS['kernel']['version']}"
    apply_kernel_patch(src)
    obj = work/'linux-obj'; obj.mkdir()
    kernel_config(src,obj)
    run(['make','-C',src,f'O={obj}','ARCH=arm64',f'-j{jobs}',
         f'KCFLAGS=-ffile-prefix-map={work}=/build','Image'])
    shutil.copyfile(obj/'arch/arm64/boot/Image',out/'Image')
    shutil.copyfile(obj/'.config',out/'kernel.config')
    cargo = rootfs(work,cache,out,lock)
    manifest = {'schema':1,'bundle_version':'0.1.0','architecture':'aarch64',
        'kernel_version':PINS['kernel']['version']+'-kiln-guest1',
        'kiln_commit':PINS['kiln_commit'],'firecracker_version':PINS['firecracker']['version'],
        'source_date_epoch':int(EPOCH),'broker':{'enabled':False,'protocol':None},
        'launch_profile':{'huge_pages':'Transparent'},
        'work_disk':{'filesystem':'xfs','mount_options':['nosuid','nodev','noexec','prjquota'],'minimum_mib':512},
        'artifacts':{name:{'sha256':sha(out/name),'bytes':(out/name).stat().st_size}
            for name in ['Image','kernel.config','kiln','rootfs.squashfs']},
        'inputs':input_provenance(cache,lock,source,cargo)}
    writejson(out/'manifest.json',manifest)
    if verify_source(ROOT)['digest'] != source['digest']: raise ValueError('source changed during build')

def build(cache, work, out, jobs, source_digest=None):
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
    if os.path.lexists(out): raise ValueError(f'refusing to overwrite {out}')
    work.mkdir(parents=True,exist_ok=False)
    os.environ.update({'SOURCE_DATE_EPOCH':EPOCH,'KBUILD_BUILD_TIMESTAMP':'2026-10-30 00:00:00 UTC',
        'KBUILD_BUILD_USER':'builder','KBUILD_BUILD_HOST':'kiln-guest','KBUILD_BUILD_VERSION':'1',
        'LC_ALL':'C','TZ':'UTC'})
    try:
        publish_new_directory(out,lambda output:assemble(cache,work,output,jobs,lock,source))
    finally:
        shutil.rmtree(work)

def validate_kiln_source(cache, lock):
    actual=sha(cache/'kiln.tar')
    if actual != lock['kiln_source_sha256'] or actual != PINS['kiln_source_sha256']:
        raise ValueError('kiln source pin/lock/archive mismatch')

def apply_kernel_patch(source):
    patch=PINS['kernel_kaslr_patch']
    original=source/patch['upstream_path']; replacement=ROOT/patch['replacement']
    if sha(original) != patch['upstream_sha256'] or sha(replacement) != patch['sha256']:
        raise ValueError('kernel KASLR source patch digest mismatch')
    shutil.copyfile(replacement,original)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare','build','configure'])
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--work',type=Path)
    parser.add_argument('--out',type=Path)
    parser.add_argument('--kiln-repo',type=Path)
    parser.add_argument('--jobs',type=int,default=3)
    parser.add_argument('--source-digest',help='stable inventory digest the staged source must match')
    args = parser.parse_args()
    for number in [signal.SIGTERM,signal.SIGHUP]: signal.signal(number,lambda *_:sys.exit(143))
    if args.action == 'prepare': prepare(args.cache.resolve(),args.kiln_repo.resolve())
    elif args.action == 'configure': configure(args.cache.resolve(),args.work.resolve())
    else: build(args.cache.resolve(),args.work.resolve(),args.out.resolve(),args.jobs,args.source_digest)
