#!/usr/bin/env python3
"""Stage or retrieve this repo without adding a shared mount. Own the VM lock."""
import argparse
import atexit
import hashlib
import io
import json
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
KILND_REPO = COMMON.parent.parent/'kilnd'
BUILD_ROOT = None  # ~/kiln-guest-build in the VM, resolved on first use

def build_root():
    global BUILD_ROOT
    if BUILD_ROOT is None:
        home = sp.check_output(['limactl','shell','--workdir','/tmp','kiln','sh','-c','printf %s "$HOME"'],text=True)
        if not home.startswith('/') or '\n' in home:
            raise RuntimeError(f'unexpected VM home directory {home!r}')
        BUILD_ROOT = f'{home}/kiln-guest-build'
    return BUILD_ROOT

def release():
    if (LOCK/'owner').exists() and (LOCK/'owner').read_text() == f'Guest launch contract {os.getpid()}\n':
        shutil.rmtree(LOCK)

def shell(command, **kwargs):
    return sp.run(['limactl','shell','--workdir','/tmp','kiln','bash','-c',command],check=True,**kwargs)

def stage_source():
    """Publish a new stage from this checkout; the VM checks it against the local digest."""
    shell('mkdir -p ~/kiln-guest-build/cache')
    inventory = source_inventory(ROOT); digest = inventory_digest(inventory)
    p = sp.Popen(['limactl','shell','--workdir','/tmp','kiln','sudo','python3','-I','-c',
                  (ROOT/'scripts/inputs.py').read_text(),'stage',f'{build_root()}/repo',digest],stdin=sp.PIPE)
    try:
        write_archive(ROOT,p.stdin,inventory)
    except BrokenPipeError: pass
    finally:
        try: p.stdin.close()
        except BrokenPipeError: pass
    if p.wait(): raise RuntimeError('staging failed')
    return digest

def stage_kiln():
    """Export only approved source bytes on the host, never execute them here."""
    pins=json.loads((ROOT/'config/pins.json').read_text())
    data=sp.check_output(['git','-C',str(KILN_REPO),'archive','--format=tar',pins['kiln_commit']])
    if hashlib.sha256(data).hexdigest()!=pins['kiln_source_sha256']:
        raise ValueError('kiln export differs from approved source pin')
    shell('cat > ~/kiln-guest-build/cache/kiln.tar',input=data)

def stage_kilnd():
    """Export the pinned kilnd commit for the guest broker; `git archive` of a commit is
    byte-identical on every export. Only approved bytes reach the VM; nothing runs here."""
    pins=json.loads((ROOT/'config/pins.json').read_text())
    data=sp.check_output(['git','-C',str(KILND_REPO),'archive','--format=tar',pins['kilnd_commit']])
    actual=hashlib.sha256(data).hexdigest()
    if actual!=pins['kilnd_source_sha256']:
        raise ValueError(f'kilnd export of {pins["kilnd_commit"]} differs from approved source pin (export {actual})')
    shell('cat > ~/kiln-guest-build/cache/kilnd.tar',input=data)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['stage','prepare','configure','build-a','build-b','test','collect','cleanup','command','snapshot','start'])
    parser.add_argument('command',nargs='?')
    parser.add_argument('--allow-unpinned-broker',action='store_true',
                        help='build-a/build-b only: the first pinning build (see build.py)')
    args = parser.parse_args()
    while True:
        try: LOCK.mkdir(); break
        except FileExistsError:
            print('VM busy:',(LOCK/'owner').read_text().strip() if (LOCK/'owner').exists() else 'owner pending',flush=True,file=sys.stderr)
            time.sleep(5)
    (LOCK/'owner').write_text(f'Guest launch contract {os.getpid()}\n')
    atexit.register(release)
    for number in [signal.SIGTERM,signal.SIGHUP]:
        signal.signal(number,lambda *_:sys.exit(143))
    try:
        if args.action == 'start':
            sp.run(['limactl','start','--tty=false','kiln'],check=True)
        elif args.action == 'stage':
            stage_source()
            source = Path('/tmp/kiln-guest-linux-6.18.56.tar.xz')
            if source.exists():
                with source.open('rb') as f: shell('cat > ~/kiln-guest-build/cache/linux.tar.xz',stdin=f)
        elif args.action == 'collect':
            dest=ROOT/'dist'; dest.mkdir(exist_ok=True)
            with (dest/'collected.tar').open('wb') as f:
                # prepare and configure results must reach the checkout before any bundle exists.
                shell('cd ~/kiln-guest-build; sudo tar -cf - $(ls -d bundle-a bundle-b repo/config results results-hardening results-launch-contract 2>/dev/null)',stdout=f)
            with tarfile.open(dest/'collected.tar') as t:
                for member in t.getmembers():
                    path=Path(member.name)
                    if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                        raise ValueError('unsafe artifact archive')
                    if path.parts[0] not in ['bundle-a','bundle-b','repo','results','results-hardening','results-launch-contract']:
                        raise ValueError('unexpected artifact archive path')
                t.extractall(dest)
            (dest/'collected.tar').unlink()
            for f in (dest/'repo/config').glob('*'): shutil.copyfile(f,ROOT/'config'/f.name)
            if (dest/'results').exists(): shutil.copytree(dest/'results',ROOT/'results',dirs_exist_ok=True)
            if (dest/'results-hardening').exists():
                shutil.copytree(dest/'results-hardening',ROOT/'results/hardening/validation',dirs_exist_ok=True)
                shutil.rmtree(dest/'results-hardening')
            if (dest/'results-launch-contract').exists():
                shutil.copytree(dest/'results-launch-contract',ROOT/'results/launch-contract/validation',dirs_exist_ok=True)
                shutil.rmtree(dest/'results-launch-contract')
            shutil.rmtree(dest/'repo')
            shutil.rmtree(dest/'results',ignore_errors=True)
        elif args.action == 'cleanup':
            shell('sudo rm -rf ~/kiln-guest-build/work-a ~/kiln-guest-build/work-b ~/kiln-guest-build/.*.tmp-*; sudo du -sh ~/kiln-guest-build/cache; pgrep -af firecracker || true')
        elif args.action == 'command': shell(args.command)
        else:
            prefix='cd ~/kiln-guest-build/repo; '
            env='sudo /usr/bin/python3 scripts/build_environment.py enter --cache ../cache -- '
            if args.action == 'snapshot':
                stage_source()
                shell(prefix+'sudo /usr/bin/python3 scripts/build_environment.py snapshot --cache ../cache --rust "$(dirname "$(dirname "$(rustup which rustc)")")"')
                return
            if args.action == 'prepare':
                stage_source()
                stage_kiln()
                stage_kilnd()
                cmd='prepare --cache /build/cache --kiln-repo /build/kiln-source'
            elif args.action == 'configure':
                stage_source()
                cmd='configure --cache /build/cache --work /build/config-work'
            elif args.action.startswith('build-'):
                name=args.action[-1]; digest=stage_source()
                stage_kilnd()
                cmd=f'build --cache /build/cache --work /build/work-{name} --out /build/bundle-{name} --source-digest {digest}'
                if args.allow_unpinned_broker: cmd+=' --allow-unpinned-broker'
            else:
                env='sudo /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin '
                cmd='python3 tests/firecracker.py --bundle ../bundle-a --cache ../cache --out ../results-launch-contract'
            shell(prefix+env+cmd)
    finally: release()

if __name__ == '__main__': main()
