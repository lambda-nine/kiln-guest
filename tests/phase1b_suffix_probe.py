#!/usr/bin/env python3
"""Measure Firecracker's appended command line per device topology (root, Linux).

Boots the existing schema 1 bundle, whose init compares /proc/cmdline exactly.
Test-mode boots print the observed line and production boots print only PASS or
FAIL, so no init change is needed. Nothing here approves a bundle.
"""
import argparse
import json
import os
from pathlib import Path
import select
import shutil
import subprocess as sp
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
sys.path.insert(0, str(ROOT))
from launch_contract import CMDLINE
from privileged_launch import TRUST_ROOT, trusted_directory
from tests.firecracker import verify_release
from verify import verify as verify_bundle

TOPOLOGIES = {
    'legacy-two-drives': (['rootfs', 'work'], False),
    'two-drives-vsock': (['rootfs', 'work'], True),
    'three-drives': (['rootfs', 'work', 'identity'], False),
    'offline-768-v1-three-drives-vsock': (['rootfs', 'work', 'identity'], True),
}


def config(base, bundle, drives, vsock, boot_args):
    paths = {'rootfs': bundle/'rootfs.squashfs', 'work': base/'work.xfs', 'identity': base/'identity'}
    value = {'boot-source': {'kernel_image_path': str(bundle/'Image'), 'boot_args': boot_args},
             'machine-config': {'vcpu_count': 1, 'mem_size_mib': 768, 'smt': False,
                                'huge_pages': 'Transparent', 'track_dirty_pages': False},
             'drives': [{'drive_id': name, 'path_on_host': str(paths[name]),
                         'is_root_device': name == 'rootfs', 'is_read_only': name != 'work'}
                        for name in drives]}
    if vsock: value['vsock'] = {'guest_cid': 5253, 'uds_path': str(base/'vsock.sock')}
    return value


def boot(fd, base, bundle, drives, vsock, boot_args, timeout):
    """Run to the cmdline verdict, then kill the VMM. Returns (verdict, line, console)."""
    disk = base/'work.xfs'
    with disk.open('wb') as f: f.truncate(536870912)
    sp.run(['mkfs.xfs', '-q', '-f', '-K', str(disk)], check=True)
    (base/'identity').write_bytes(bytes(4096))
    path = base/'config.json'
    path.write_text(json.dumps(config(base, bundle, drives, vsock, boot_args)))
    if (base/'vsock.sock').exists(): (base/'vsock.sock').unlink()
    p = sp.Popen(['/firecracker', '--no-api', '--config-file', str(path)], executable=f'/proc/self/fd/{fd}',
                 pass_fds=(fd,), stdin=sp.DEVNULL, stdout=sp.PIPE, stderr=sp.STDOUT, cwd=base)
    console, line, verdict = b'', None, None
    deadline = time.monotonic() + timeout
    try:
        while verdict is None and time.monotonic() < deadline and p.poll() is None:
            if select.select([p.stdout], [], [], 0.2)[0]:
                chunk = os.read(p.stdout.fileno(), 65536)
                if not chunk: break
                console += chunk
            # A partial trailing line must not count: 'P' is not a verdict.
            for raw in console[:console.rfind(b'\n') + 1].splitlines():
                text = raw.decode('utf-8', 'replace').strip()
                if text.startswith('KG_CMDLINE <') and text.endswith('>'): line = text[12:-1]
                if text.startswith('KG_RUNTIME cmdline '): verdict = text.split()[-1]
    finally:
        p.kill(); p.wait()
    return verdict, line, console.decode('utf-8', 'replace')[-4096:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    args.bundle = args.bundle.resolve()
    verify_bundle(args.bundle)
    fds = {}
    verify_release(args.cache, opened=fds)
    fd = fds['firecracker'][1]
    private = trusted_directory(TRUST_ROOT, create=True); os.close(private)
    base = Path(tempfile.mkdtemp(prefix='suffix-probe-', dir=TRUST_ROOT))
    records = {}
    try:
        for name, (drives, vsock) in TOPOLOGIES.items():
            verdict, line, console = boot(fd, base, args.bundle, drives, vsock, CMDLINE+' kiln.test=1', args.timeout)
            suffix = line[len(CMDLINE+' kiln.test=1'):] if line and line.startswith(CMDLINE+' kiln.test=1') else None
            production, _, production_console = boot(fd, base, args.bundle, drives, vsock, CMDLINE, args.timeout)
            records[name] = {'drives': drives, 'vsock': vsock, 'test_mode_observed_cmdline': line,
                             'observed_suffix': suffix, 'legacy_init_verdict_test_mode': verdict,
                             'legacy_init_verdict_production_args': production,
                             'console_tail': console, 'production_console_tail': production_console}
            print(name, repr(suffix), verdict, production, flush=True)
            if verdict is None or production is None:
                raise SystemExit(f'{name}: no init verdict before timeout:\n{console}')
    finally:
        for _, retained in fds.values(): os.close(retained)
        shutil.rmtree(base)
    result = {'kernel': os.uname().release, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'firecracker_archive_sha256': json.loads((ROOT/'config/pins.json').read_text())['firecracker']['sha256'],
              'bundle_rootfs_sha256': verify_bundle(args.bundle)['artifacts']['rootfs.squashfs']['sha256'],
              'launch_args': 'firecracker --no-api --config-file; no jailer; root; nested KVM',
              'topologies': records}
    args.out.write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')


if __name__ == '__main__': main()
