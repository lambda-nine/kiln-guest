"""Adversarial checks for validation inputs and serial observation."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tests import firecracker as fc
import build

class ValidationTests(unittest.TestCase):
    def test_actual_kaslr_seed_function_handles_and_erases_seeds(self):
        source=(fc.ROOT/'src/kernel-kaslr-early.c').read_text()
        function=source[source.index('static u64 __init get_kaslr_seed'):source.index('\nu64 __init kaslr_early_init')]
        fixture=(fc.ROOT/'tests/kaslr_seed_fixture.c').read_text().replace('/* KERNEL_FUNCTION */',function)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d); (path/'probe.c').write_text(fixture)
            subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror',
                            str(path/'probe.c'),'-o',str(path/'probe')],check=True,capture_output=True)
            result=subprocess.run([str(path/'probe')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_kernel_patch_requires_both_reviewed_source_hashes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=root/'linux'; source.mkdir()
            original=source/'kaslr.c'; original.write_bytes(b'upstream')
            replacement=root/'replacement.c'; replacement.write_bytes(b'reviewed')
            pins={'kernel_kaslr_patch':{'upstream_path':'kaslr.c','replacement':'replacement.c',
                  'upstream_sha256':hashlib.sha256(b'upstream').hexdigest(),
                  'sha256':hashlib.sha256(b'reviewed').hexdigest()}}
            with mock.patch.object(build,'ROOT',root),mock.patch.object(build,'PINS',pins):
                replacement.write_bytes(b'tampered')
                with self.assertRaisesRegex(ValueError,'patch digest'): build.apply_kernel_patch(source)
                self.assertEqual(original.read_bytes(),b'upstream')
                replacement.write_bytes(b'reviewed'); original.write_bytes(b'drift')
                with self.assertRaisesRegex(ValueError,'patch digest'): build.apply_kernel_patch(source)
                self.assertEqual(original.read_bytes(),b'drift')
                original.write_bytes(b'upstream'); build.apply_kernel_patch(source)
                self.assertEqual(original.read_bytes(),b'reviewed')

    def test_coalesced_markers_keep_their_first_observation(self):
        with tempfile.TemporaryDirectory() as d:
            read, write = os.pipe()
            pipe = os.fdopen(read, 'rb', buffering=0)
            self.addCleanup(pipe.close); self.addCleanup(os.close, write)
            vm = object.__new__(fc.VM)
            vm.p=SimpleNamespace(stdout=pipe); vm.buf=b''; vm.observations=[]
            vm.out=Path(d); vm.name='fixture'; vm.start=fc.time.monotonic_ns()
            os.write(write,b'KG_FIRST_COMMAND\nKG_READY\n')
            first=vm.until(b'KG_FIRST_COMMAND',timeout=.05)
            ready=vm.until(b'KG_READY',timeout=.05)
            self.assertEqual(first,ready)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'requires Linux root trust tree')
    def test_modified_vmm_and_adjacent_checksum_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            cache=Path(d); archive=cache/'firecracker.tgz'
            folder='release-v1.17.0-aarch64'
            with tarfile.open(archive,'w:gz') as tar:
                for name in ['firecracker','jailer']:
                    data=(name+' trusted').encode()
                    info=tarfile.TarInfo(f'{folder}/{name}-v1.17.0-aarch64')
                    info.size=len(data); info.mode=0o755
                    tar.addfile(info,io.BytesIO(data))
            expected=hashlib.sha256(archive.read_bytes()).hexdigest()
            release=fc.verify_release(cache,expected)
            self.addCleanup(shutil.rmtree,release)
            executable=release/folder/'firecracker-v1.17.0-aarch64'
            executable.chmod(0o755)
            executable.write_bytes(b'attacker executable')
            (executable.parent/'SHA256SUMS').write_text(hashlib.sha256(executable.read_bytes()).hexdigest()+'  '+executable.name+'\n')
            with self.assertRaisesRegex(ValueError,'VMM executable'):
                fc.verify_release(cache,expected)

    def test_old_matching_lock_and_archive_cannot_mislabel_new_pin(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'config').mkdir(); cache=root/'cache'; cache.mkdir()
            archive=cache/'kiln.tar'; archive.write_bytes(b'old kiln source')
            old=hashlib.sha256(archive.read_bytes()).hexdigest()
            (root/'config/build-lock.json').write_text(json.dumps({'toolchain':{},'kiln_source_sha256':old}))
            with mock.patch.object(build,'ROOT',root), \
                 mock.patch.object(build,'verify_source',return_value={'digest':'source','files':[]}), \
                 mock.patch.object(build,'toolchain',return_value={}), \
                 mock.patch.object(build,'fetch'), mock.patch.object(build,'assemble') as assemble, \
                 mock.patch.object(build.os,'geteuid',return_value=0), \
                 mock.patch.object(build.os,'uname',return_value=SimpleNamespace(machine='aarch64')):
                with self.assertRaisesRegex(ValueError,'pin/lock/archive'):
                    build.build(cache,root/'work',root/'out',1)
                assemble.assert_not_called()
            self.assertFalse((root/'work').exists())
            self.assertFalse((root/'out').exists())

if __name__=='__main__': unittest.main()
