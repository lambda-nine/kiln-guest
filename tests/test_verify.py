"""Admission checks must still reject corrupted bundles with Python -O."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

VERIFY=Path(__file__).resolve().parents[1]/'scripts/verify.py'

class VerifyTests(unittest.TestCase):
    def test_diagnostic_bundle_is_rejected_for_acceptance(self):
        with tempfile.TemporaryDirectory() as d:
            a=self.bundle(Path(d)/'a')
            manifest=json.loads((a/'manifest.json').read_text()); manifest['diagnostic_only']='experiment'
            (a/'manifest.json').write_text(json.dumps(manifest))
            result=self.call(a)
            self.assertNotEqual(result.returncode,0)
            self.assertIn(b'diagnostic bundle',result.stderr)

    def bundle(self, path):
        path.mkdir()
        artifacts={}
        for name in ['Image','kernel.config','kiln','rootfs.squashfs']:
            data=('fixture '+name).encode(); (path/name).write_bytes(data)
            artifacts[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        (path/'manifest.json').write_text(json.dumps({'schema':1,'artifacts':artifacts,'launch_contract':__import__('launch_contract').contract()}))
        return path

    def call(self,*paths):
        return subprocess.run([sys.executable,'-O',str(VERIFY),*map(str,paths)],capture_output=True)

    def test_two_identical_builds(self):
        with tempfile.TemporaryDirectory() as d:
            a=self.bundle(Path(d)/'a'); b=self.bundle(Path(d)/'b')
            result=self.call(a,b)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue(json.loads(result.stdout)['reproducible'])

    def test_same_size_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a=self.bundle(Path(d)/'a')
            data=bytearray((a/'Image').read_bytes()); data[0]^=1; (a/'Image').write_bytes(data)
            self.assertNotEqual(self.call(a).returncode,0)

    def test_unknown_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a=self.bundle(Path(d)/'a')
            manifest=json.loads((a/'manifest.json').read_text()); manifest['schema']=2
            (a/'manifest.json').write_text(json.dumps(manifest))
            self.assertNotEqual(self.call(a).returncode,0)

if __name__=='__main__': unittest.main()
