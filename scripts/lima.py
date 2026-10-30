#!/usr/bin/env python3
"""Stage or retrieve this repo without adding a shared mount. Own the VM lock."""
import argparse
import atexit
from pathlib import Path
import os
import shutil
import signal
import subprocess as sp
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT.parent/'.vm-lock'

def release():
    if (LOCK/'owner').exists() and (LOCK/'owner').read_text() == f'Guest image {os.getpid()}\n':
        shutil.rmtree(LOCK)

def shell(command, **kwargs):
    return sp.run(['limactl','shell','--workdir','/tmp','kiln','bash','-c',command],check=True,**kwargs)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['stage','prepare','build-a','build-b','test','collect','cleanup','command'])
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
            shell('mkdir -p ~/kiln-guest-build/repo ~/kiln-guest-build/cache')
            p = sp.Popen(['limactl','shell','--workdir','/tmp','kiln','sudo','tar','-xf','-','-C','/home/estradafamily.guest/kiln-guest-build/repo'],stdin=sp.PIPE)
            with tarfile.open(fileobj=p.stdin,mode='w|') as tar:
                for f in sorted(ROOT.rglob('*')):
                    rel=f.relative_to(ROOT)
                    if not f.is_file() or any(s in ['.git','__pycache__','dist'] for s in rel.parts): continue
                    tar.add(f,arcname=str(rel),recursive=False)
            p.stdin.close()
            if p.wait(): raise RuntimeError('staging failed')
            source = Path('/tmp/kiln-guest-linux-6.18.56.tar.xz')
            if source.exists():
                with source.open('rb') as f: shell('cat > ~/kiln-guest-build/cache/linux.tar.xz',stdin=f)
        elif args.action == 'collect':
            dest=ROOT/'dist'; dest.mkdir(exist_ok=True)
            with (dest/'collected.tar').open('wb') as f:
                shell('sudo tar -C ~/kiln-guest-build -cf - bundle-a bundle-b repo/config results',stdout=f)
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
            shell('sudo rm -rf ~/kiln-guest-build/work-a ~/kiln-guest-build/work-b; sudo du -sh ~/kiln-guest-build/cache; pgrep -af firecracker || true')
        elif args.action == 'command': shell(args.command)
        else:
            prefix='task_bin=$(dirname "$(rustup which rustc)"); export PATH="$task_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; cd ~/kiln-guest-build/repo; '
            env='sudo env PATH="$PATH" CARGO_HOME="$HOME/kiln-guest-build/cache/cargo" '
            if args.action == 'prepare':
                cmd='python3 scripts/build.py prepare --cache ../cache --kiln-repo /Users/estradafamily/Projects/lambda-nine/kiln'
            elif args.action.startswith('build-'):
                name=args.action[-1]; cmd=f'python3 scripts/build.py build --cache ../cache --work ../work-{name} --out ../bundle-{name}'
            else: cmd='python3 tests/firecracker.py --bundle ../bundle-a --cache ../cache --out ../results'
            shell(prefix+env+cmd)
    finally: release()

if __name__ == '__main__': main()
