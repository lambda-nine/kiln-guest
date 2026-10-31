#!/usr/bin/env python3
"""Kernel-only experiment, not an independent bundle build."""
import os
from pathlib import Path
import shutil
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import build

base=Path.cwd().parent
work=base/'trace-kernel-work'
work.mkdir(exist_ok=False)
try:
    build.unpack(base/'cache/linux.tar.xz',work/'linux-source')
    source=work/'linux-source'/('linux-'+build.PINS['kernel']['version'])
    build.apply_kernel_patch(source)
    patch=build.PINS['kernel_clear_page_patch']
    original=source/patch['upstream_path']; replacement=build.ROOT/patch['replacement']
    assert build.sha(original)==patch['upstream_sha256']
    assert build.sha(replacement)==patch['sha256']
    shutil.copyfile(replacement,original)
    obj=work/'linux-obj'; obj.mkdir()
    build.kernel_config(source,obj)
    os.environ.update({'KBUILD_BUILD_TIMESTAMP':'2026-10-30 00:00:00 UTC',
                       'KBUILD_BUILD_USER':'builder','KBUILD_BUILD_HOST':'kiln-guest','KBUILD_BUILD_VERSION':'1'})
    build.run(['make','-C',source,f'O={obj}','ARCH=arm64','-j3',
               f'KCFLAGS=-ffile-prefix-map={work}=/build','Image'])
    dest=base/'trace-store-bundle'; shutil.copytree(base/'trace-bundle',dest)
    shutil.copyfile(obj/'arch/arm64/boot/Image',dest/'Image')
    import json
    manifest=json.loads((dest/'manifest.json').read_text())
    manifest['inputs']['kernel_experiment']={
        'kernel_archive_sha256':build.sha(base/'cache/linux.tar.xz'),
        'kernel_config_sha256':build.sha(obj/'.config'),
        'kaslr_patch':build.PINS['kernel_kaslr_patch'],
        'clear_page_patch':build.PINS['kernel_clear_page_patch']}
    manifest['artifacts']['Image']={'sha256':build.sha(dest/'Image'),'bytes':(dest/'Image').stat().st_size}
    build.writejson(dest/'manifest.json',manifest)
finally:
    shutil.rmtree(work)
