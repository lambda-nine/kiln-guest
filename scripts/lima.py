#!/usr/bin/env python3
"""Stage or retrieve this repo without adding a shared mount. Own the VM lock."""
import argparse
import atexit
from pathlib import Path
import os
import shlex
import shutil
import signal
import subprocess as sp
import sys
import tarfile
import time
from inputs import inventory_digest, source_inventory, write_archive

ROOT = Path(__file__).resolve().parents[1]
COMMON = Path(sp.check_output(['git','-C',str(ROOT),'rev-parse','--path-format=absolute','--git-common-dir'],text=True).strip())
LOCK = COMMON.parent.parent/'.vm-lock'
KILN_REPO = COMMON.parent.parent/'kiln'
BUILD_ROOT = '/home/estradafamily.guest/kiln-guest-build'

def release():
    if (LOCK/'owner').exists() and (LOCK/'owner').read_text() == f'Guest image {os.getpid()}\n':
        shutil.rmtree(LOCK)

def shell(command, **kwargs):
    return sp.run(['limactl','shell','--workdir','/tmp','kiln','bash','-c',command],check=True,**kwargs)

def stage_source():
    """Publish a new stage from this checkout; the VM checks it against the local digest."""
    shell('mkdir -p ~/kiln-guest-build/cache')
    inventory = source_inventory(ROOT); digest = inventory_digest(inventory)
    p = sp.Popen(['limactl','shell','--workdir','/tmp','kiln','sudo','python3','-I','-c',
                  (ROOT/'scripts/inputs.py').read_text(),'stage',f'{BUILD_ROOT}/repo',digest],stdin=sp.PIPE)
    try:
        write_archive(ROOT,p.stdin,inventory)
    except BrokenPipeError: pass
    finally:
        try: p.stdin.close()
        except BrokenPipeError: pass
    if p.wait(): raise RuntimeError('staging failed')
    return digest

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['stage','prepare','configure','build-a','build-b','test','collect','cleanup','command'])
    parser.add_argument('command',nargs='?')
    args = parser.parse_args()
    while True:
        try: LOCK.mkdir(); break
        except FileExistsError:
            print('VM busy:',(LOCK/'owner').read_text().strip() if (LOCK/'owner').exists() else 'owner pending',flush=True,file=sys.stderr)
            time.sleep(180)
    (LOCK/'owner').write_text(f'Guest image {os.getpid()}\n')
    atexit.register(release)
    signal.signal(signal.SIGTERM,lambda *_:sys.exit(143))
    try:
        if args.action == 'stage':
            stage_source()
            source = Path('/tmp/kiln-guest-linux-6.18.56.tar.xz')
            if source.exists():
                with source.open('rb') as f: shell('cat > ~/kiln-guest-build/cache/linux.tar.xz',stdin=f)
        elif args.action == 'collect':
            dest=ROOT/'dist'; dest.mkdir(exist_ok=True)
            with (dest/'collected.tar').open('wb') as f:
                # prepare and configure results must reach the checkout before any bundle exists.
                shell('cd ~/kiln-guest-build; sudo tar -cf - $(ls -d bundle-a bundle-b repo/config results 2>/dev/null)',stdout=f)
            with tarfile.open(dest/'collected.tar') as t:
                for member in t.getmembers():
                    path=Path(member.name)
                    if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                        raise ValueError('unsafe artifact archive')
                    if path.parts[0] not in ['bundle-a','bundle-b','repo','results']:
                        raise ValueError('unexpected artifact archive path')
                t.extractall(dest)
            (dest/'collected.tar').unlink()
            for f in (dest/'repo/config').glob('*'): shutil.copyfile(f,ROOT/'config'/f.name)
            if (dest/'results').exists(): shutil.copytree(dest/'results',ROOT/'results',dirs_exist_ok=True)
            shutil.rmtree(dest/'repo')
            shutil.rmtree(dest/'results',ignore_errors=True)
        elif args.action == 'cleanup':
            shell('sudo rm -rf ~/kiln-guest-build/work-a ~/kiln-guest-build/work-b ~/kiln-guest-build/.*.tmp-*; sudo du -sh ~/kiln-guest-build/cache; pgrep -af firecracker || true')
        elif args.action == 'command': shell(args.command)
        else:
            prefix='task_bin=$(dirname "$(rustup which rustc)"); export PATH="$task_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; cd ~/kiln-guest-build/repo; '
            env='sudo env PATH="$PATH" '
            if args.action == 'prepare':
                stage_source()
                cmd=f'python3 scripts/build.py prepare --cache ../cache --kiln-repo {shlex.quote(str(KILN_REPO))}'
            elif args.action == 'configure':
                stage_source()
                cmd='python3 scripts/build.py configure --cache ../cache --work ../config-work'
            elif args.action.startswith('build-'):
                name=args.action[-1]; digest=stage_source()
                cmd=f'python3 scripts/build.py build --cache ../cache --work ../work-{name} --out ../bundle-{name} --source-digest {digest}'
            else: cmd='python3 tests/firecracker.py --bundle ../bundle-a --cache ../cache --out ../results'
            shell(prefix+env+cmd)
    finally: release()

if __name__ == '__main__': main()
