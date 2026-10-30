#!/usr/bin/env python3
"""Repack only PID 1 for diagnosis, never an independent build or acceptance."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import build
from verify import verify

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['bundle','out','work']: p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    verify(a.bundle)
    a.work.mkdir(parents=True,exist_ok=False); a.out.mkdir(parents=True,exist_ok=False)
    try:
        tree=a.work/'root'
        build.run(['unsquashfs','-no-progress','-d',tree,a.bundle/'rootfs.squashfs'])
        build.run(['gcc','-static','-Os','-Wall','-Wextra','-Werror','-fstack-protector-strong',
                   '-D_FORTIFY_SOURCE=2','-Wl,--build-id=none','-o',tree/'init',build.ROOT/'src/init.c'])
        build.run(['strip','--strip-all',tree/'init'])
        env=os.environ.copy(); env.pop('SOURCE_DATE_EPOCH',None)
        build.run(['mksquashfs',tree,a.out/'rootfs.squashfs','-noappend','-comp','gzip',
                   '-processors','1','-no-xattrs','-no-exports','-no-fragments',
                   '-all-time',build.EPOCH,'-mkfs-time',build.EPOCH,'-no-progress'],env=env)
        for name in ['Image','kernel.config','kiln']: shutil.copyfile(a.bundle/name,a.out/name)
        manifest=json.loads((a.bundle/'manifest.json').read_text())
        (a.out/'base-manifest.json').write_bytes((a.bundle/'manifest.json').read_bytes())
        manifest['diagnostic_only']='Repacked PID 1; not an independent build'
        manifest['inputs']={'base_manifest_sha256':build.sha(a.bundle/'manifest.json'),
                            'compiler':{'path':shutil.which('gcc'),'sha256':build.sha(Path(shutil.which('gcc')).resolve())},
                            'init_sources':{str(path.relative_to(build.ROOT)):build.sha(path)
                              for path in [build.ROOT/'src/init.c',*sorted((build.ROOT/'src').glob('*.h'))]}}
        for name in manifest['artifacts']:
            manifest['artifacts'][name]={'bytes':(a.out/name).stat().st_size,'sha256':build.sha(a.out/name)}
        build.writejson(a.out/'manifest.json',manifest)
    finally: shutil.rmtree(a.work)

if __name__=='__main__': main()
