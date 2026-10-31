#!/usr/bin/env python3
"""Create once, review/pin, then mount an immutable measured build rootfs.

No package installation or downloaded executable is run. The snapshot is of
this VM's installed distribution and selected Rust toolchain. It is NOT an
independent supply-chain authority. Every regular file and symlink is measured.
"""
import argparse
import array
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess as sp
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
FIXED_PATH='/opt/rust/bin:/usr/sbin:/usr/bin'

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()

def verify_image(image, lock):
    if not image.is_file() or sha(image)!=lock['sha256']:
        raise ValueError('build rootfs digest mismatch')
    if lock['path']!=FIXED_PATH:
        raise ValueError('build PATH differs from fixed policy')

def snapshot(cache,rust):
    dest=ROOT/'config/build-environment.json'
    if dest.exists(): raise ValueError('refusing silent build-environment repin')
    image=cache/'toolchain.squashfs'
    if image.exists(): raise ValueError('refusing image overwrite')
    with tempfile.TemporaryDirectory(prefix='toolchain-',dir=cache.parent) as tmp:
        tree=Path(tmp)
        for d in ['usr','opt','etc','var/lib/dpkg','var/lib/apt/lists','build','tmp','proc','dev','root']:
            (tree/d).mkdir(parents=True,exist_ok=True)
        # A complete installed /usr also binds compiler specs, Python modules,
        # linker scripts, crt objects, headers, helpers and shared libraries.
        sp.run(['/usr/bin/cp','-a','/usr/.',str(tree/'usr')],check=True)
        shutil.rmtree(tree/'usr/local',ignore_errors=True)
        sp.run(['/usr/bin/cp','-a',str(rust),str(tree/'opt/rust')],check=True)
        for name in ['bin','sbin','lib','lib64']:
            p=Path('/'+name)
            if p.is_symlink(): (tree/name).symlink_to(os.readlink(p))
        for name in ['alternatives','ssl','apt','ld.so.cache','ld.so.conf','ld.so.conf.d','nsswitch.conf','hosts','resolv.conf']:
            p=Path('/etc')/name; q=tree/'etc'/name
            if p.is_dir(): shutil.copytree(p,q,symlinks=True)
            elif p.exists(): shutil.copyfile(p,q)
        shutil.copyfile('/var/lib/dpkg/status',tree/'var/lib/dpkg/status')
        sp.run(['/usr/bin/cp','-a','/var/lib/apt/lists/.',str(tree/'var/lib/apt/lists')],check=True)
        records={}
        for p in sorted(tree.rglob('*')):
            name='/'+str(p.relative_to(tree))
            if p.is_symlink(): records[name]={'symlink':os.readlink(p)}
            elif p.is_file(): records[name]={'sha256':sha(p),'mode':p.stat().st_mode & 0o7777}
        inventory=ROOT/'config/toolchain-files.json'
        inventory.write_text(json.dumps(records,sort_keys=True,separators=(',',':'))+'\n')
        sp.run(['/usr/bin/mksquashfs',str(tree),str(image),'-noappend','-comp','gzip',
                '-processors','2','-no-progress','-all-root'],check=True)
    dest.write_text(json.dumps({'schema':1,'sha256':sha(image),'bytes':image.stat().st_size,
        'inventory_sha256':sha(inventory),'path':FIXED_PATH},sort_keys=True,indent=2)+'\n')

def enter(cache,argv):
    lock=json.loads((ROOT/'config/build-environment.json').read_text())
    verify_image(cache/'toolchain.squashfs',lock)
    if sha(ROOT/'config/toolchain-files.json')!=lock['inventory_sha256']:
        raise ValueError('toolchain inventory mismatch')
    # Mount and chroot in a private namespace. No host writable PATH prefix,
    # inherited loader variables, Python paths or user config reaches the build.
    image_fd=os.open(cache/'toolchain.squashfs',os.O_RDONLY|os.O_NOFOLLOW)
    metadata=os.fstat(image_fd)
    if metadata.st_uid!=0 or metadata.st_mode & 0o022:
        os.close(image_fd); raise ValueError('build image must be root-owned and not writable by other users')
    # FS_IMMUTABLE_FL prevents even build-root's CHOWN/FOWNER/DAC capabilities
    # from changing the mounted backing file through the writable cache bind.
    flags=array.array('L',[0]); fcntl.ioctl(image_fd,0x80086601,flags,True)
    flags[0] |= 0x10; fcntl.ioctl(image_fd,0x40086602,flags)
    if sha(Path(f'/proc/self/fd/{image_fd}'))!=lock['sha256']:
        os.close(image_fd); raise ValueError('build rootfs changed before mount')
    with tempfile.TemporaryDirectory(prefix='build-root-',dir=cache.parent) as tmp:
        root=Path(tmp)
        script='''set -eu
mount --make-rprivate /
mount --no-canonicalize -t squashfs -o loop,ro,nodev,nosuid "$1" "$2"
mount --bind "$3" "$2/build"

mount -t tmpfs -o mode=1777 tmpfs "$2/tmp"
mount -t tmpfs -o mode=0700 tmpfs "$2/root"
mount -t proc proc "$2/proc"
mount -t tmpfs -o mode=0755 tmpfs "$2/dev"
for name in null zero random urandom; do
    touch "$2/dev/$name"
    mount --bind "/dev/$name" "$2/dev/$name"
done
ln -s /proc/self/fd "$2/dev/fd"
build_root="$2"
image_fd="$4"
eval "exec ${image_fd}<&-"
shift 4
exec chroot "$build_root" /usr/bin/setpriv --bounding-set=-all,+chown,+fowner,+dac_override --no-new-privs /usr/bin/env -i PATH=/opt/rust/bin:/usr/sbin:/usr/bin HOME=/root LC_ALL=C TZ=UTC KG_BUILD_ROOTFS=1 /usr/bin/python3 /build/repo/scripts/build.py "$@"
'''
        try:
            sp.run(['/usr/bin/unshare','--mount','--pid','--fork','/bin/bash','-c',script,'build-root',
                f'/proc/self/fd/{image_fd}',str(root),str(cache.parent),str(image_fd),*argv],check=True,pass_fds=(image_fd,))
        finally: os.close(image_fd)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['snapshot','enter']);p.add_argument('--cache',type=Path,required=True)
    p.add_argument('--rust',type=Path)
    boundary=sys.argv.index('--') if '--' in sys.argv else len(sys.argv)
    a=p.parse_args(sys.argv[1:boundary]); extra=sys.argv[boundary+1:]
    if a.action=='snapshot': snapshot(a.cache.resolve(),a.rust.resolve())
    else: enter(a.cache.resolve(),extra[1:] if extra[:1]==['--'] else extra)
