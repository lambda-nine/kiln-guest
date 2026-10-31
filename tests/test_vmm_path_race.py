"""KR-05: the build user's source-parent swap cannot change privileged execution."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess as sp
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from tests import firecracker as fc
from launch_contract import contract
from privileged_launch import TRUST_ROOT, trusted_directory, verified_open, atomic_copy, copy_artifact

@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'requires Linux root and privilege drop')
class VmmPathRaceTests(unittest.TestCase):
    def setUp(self):
        fd=trusted_directory(TRUST_ROOT,create=True); os.close(fd)
        self.private=Path(tempfile.mkdtemp(prefix='regression-',dir=TRUST_ROOT))
        self.addCleanup(shutil.rmtree,self.private)

    def as_user(self, code, *args):
        def drop(): os.setgroups([]); os.setgid(10001); os.setuid(10001)
        return sp.run([sys.executable,'-c',code,*map(str,args)],preexec_fn=drop,capture_output=True)

    def test_source_parent_swap_and_fd_execution(self):
        # Mirror the PoC's root-owned child beneath a build-user-owned cache.
        with tempfile.TemporaryDirectory() as d:
            cache=Path(d); os.chown(cache,10001,10001); cache.chmod(0o775)
            folder='release-v1.17.0-aarch64'
            approved=Path('/usr/bin/true').read_bytes()
            with tarfile.open(cache/'firecracker.tgz','w:gz') as tar:
                for name in ['firecracker','jailer']:
                    info=tarfile.TarInfo(f'{folder}/{name}-v1.17.0-aarch64'); info.size=len(approved)
                    tar.addfile(info,io.BytesIO(approved))
            digest=hashlib.sha256((cache/'firecracker.tgz').read_bytes()).hexdigest()
            opened={}
            with mock.patch.object(fc,'TRUST_ROOT',self.private):
                release=fc.verify_release(cache,digest,opened=opened)
            self.addCleanup(lambda: [os.close(fd) for _,fd in opened.values()])
            jailer,fd=opened['jailer']
            (cache/'release').mkdir()  # the old topology, now unused
            attack=self.as_user('''
from pathlib import Path
import sys
cache=Path(sys.argv[1]); (cache/'release').rename(cache/'approved-release')
(cache/'release').mkdir(); (cache/'release/jailer').write_text('FAKE')
''',cache)
            self.assertEqual(attack.returncode,0,attack.stderr)
            denied=self.as_user('import os,sys; os.rename(sys.argv[1],sys.argv[1]+"-swapped")',release)
            self.assertNotEqual(denied.returncode,0)
            self.assertEqual(sp.run([str(jailer)],executable=f'/proc/self/fd/{fd}',pass_fds=(fd,)).returncode,0)
            self.assertEqual(hashlib.sha256(jailer.read_bytes()).digest(),hashlib.sha256(approved).digest())
            # Stronger than the build-user threat: even a root path replacement
            # after verification cannot redirect the held jailer descriptor.
            atomic_copy(io.BytesIO(Path('/usr/bin/false').read_bytes()),jailer,
                        hashlib.sha256(Path('/usr/bin/false').read_bytes()).hexdigest(),True)
            self.assertEqual(sp.run([str(jailer)]).returncode,1)
            self.assertEqual(sp.run([str(jailer)],executable=f'/proc/self/fd/{fd}',pass_fds=(fd,)).returncode,0)

    def test_vm_executes_held_jailer_inode(self):
        # Exercise the real launcher, replacing its installed pathname at the
        # actual Popen boundary. Only the fixture VMM runs; no KVM is required.
        with tempfile.TemporaryDirectory() as d:
            cache=Path(d); bundle=cache/'bundle'; bundle.mkdir()
            out=cache/'out'; out.mkdir()
            artifacts={}
            for name in ['Image','rootfs.squashfs']:
                data=name.encode(); (bundle/name).write_bytes(data)
                artifacts[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
            manifest={'launch_contract':contract(),'artifacts':artifacts}
            approved=Path('/usr/bin/true').read_bytes()
            with tarfile.open(cache/'firecracker.tgz','w:gz') as tar:
                for name in ['firecracker','jailer']:
                    info=tarfile.TarInfo(f'release-v1.17.0-aarch64/{name}-v1.17.0-aarch64')
                    info.size=len(approved); tar.addfile(info,io.BytesIO(approved))
            digest=hashlib.sha256((cache/'firecracker.tgz').read_bytes()).hexdigest()
            real_popen=sp.Popen
            def race(argv, **kwargs):
                jailer=Path(argv[0]); replacement=Path('/usr/bin/false').read_bytes()
                atomic_copy(io.BytesIO(replacement),jailer,hashlib.sha256(replacement).hexdigest(),True)
                self.assertTrue(kwargs['executable'].startswith('/proc/self/fd/'))
                self.assertEqual(len(kwargs['pass_fds']),1)
                return real_popen(argv,**kwargs)
            with mock.patch.object(fc,'TRUST_ROOT',self.private), \
                 mock.patch.object(fc,'PINS',{'firecracker':{'sha256':digest}}), \
                 mock.patch.object(fc,'verify_bundle',return_value=manifest), \
                 mock.patch.object(fc,'run'),mock.patch.object(fc.sp,'Popen',side_effect=race):
                vm=fc.VM('race',bundle,cache,out,memory_backing='Transparent')
            try: self.assertEqual(vm.p.wait(timeout=5),0)
            finally: vm.stop()

    def test_unsafe_components_symlinks_and_modified_file_rejected(self):
        child=self.private/'child'; child.mkdir(); binary=child/'vmm'; binary.write_bytes(b'approved')
        digest=hashlib.sha256(binary.read_bytes()).hexdigest()
        for mode in [0o777,0o775]:
            child.chmod(mode)
            with self.assertRaises(ValueError): verified_open(binary,digest)
        child.chmod(0o755); os.chown(child,10001,10001)
        with self.assertRaises(ValueError): verified_open(binary,digest)
        os.chown(child,0,0)
        link=self.private/'link'; link.symlink_to(child,target_is_directory=True)
        with self.assertRaises(OSError): verified_open(link/'vmm',digest)
        binary.chmod(0o666)
        with self.assertRaises(ValueError): verified_open(binary,digest)
        binary.chmod(0o444); binary.write_bytes(b'tampered')
        with self.assertRaises(ValueError): verified_open(binary,digest)

    def test_artifact_source_swap_refused_before_use(self):
        source=self.private/'source'; source.write_bytes(b'approved')
        record={'bytes':8,'sha256':hashlib.sha256(b'approved').hexdigest()}
        source.write_bytes(b'attacker')
        with self.assertRaises(ValueError): copy_artifact(source,self.private/'kernel',record)
        self.assertFalse((self.private/'kernel').exists())
