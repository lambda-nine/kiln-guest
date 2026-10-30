"""Diagnostic evidence must fail closed before launching changed artifacts."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from tests import trace_boot
from tests import boot_options

class TraceTests(unittest.TestCase):
    def test_comparison_launch_failure_is_retained_and_cannot_be_retried_away(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); bundle=self.fixture(root)
            argv=['boot_options.py','--bundle',str(bundle),'--cache',str(root/'cache'),
                  '--out',str(root/'out'),'--option','thp','--count','1']
            read_text=Path.read_text
            def read(path,*args,**kwargs):
                if str(path)=='/proc/sys/kernel/random/boot_id': return 'fixture-boot\n'
                if str(path).startswith('/sys/kernel/mm/transparent_hugepage/'): return '[madvise]\n'
                return read_text(path,*args,**kwargs)
            with mock.patch('sys.argv',argv),mock.patch.object(boot_options.Path,'read_text',read), \
                 mock.patch.object(boot_options.fc,'verify_release'), \
                 mock.patch.object(boot_options.fc,'VM',side_effect=RuntimeError('launch failed')) as launch:
                with self.assertRaisesRegex(RuntimeError,'launch failed'): boot_options.main()
                records=(root/'out/records.jsonl').read_text().splitlines()
                self.assertEqual(len(records),1)
                self.assertFalse(json.loads(records[0])['ok'])
                self.assertEqual(json.loads(records[0])['error'],'launch failed')
                with self.assertRaisesRegex(ValueError,'nonsequential'): boot_options.main()
                self.assertEqual(launch.call_count,1)
                self.assertEqual((root/'out/records.jsonl').read_text().splitlines(),records)

    def fixture(self,root):
        bundle=root/'bundle'; bundle.mkdir()
        artifacts={}
        for name in ['Image','kernel.config','kiln','rootfs.squashfs']:
            data=name.encode(); (bundle/name).write_bytes(data)
            artifacts[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        (bundle/'manifest.json').write_text(json.dumps({'schema':1,'artifacts':artifacts}))
        return bundle

    def test_tampered_artifact_prevents_vm_launch(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); bundle=self.fixture(root)
            (bundle/'Image').write_bytes(b'wrong')
            argv=['trace_boot.py','--bundle',str(bundle),'--cache',str(root/'cache'),'--out',str(root/'out')]
            with mock.patch('sys.argv',argv),mock.patch.object(trace_boot.fc,'VM') as launch:
                with self.assertRaisesRegex(ValueError,'digest mismatch'): trace_boot.main()
                launch.assert_not_called()

    def test_failed_launch_keeps_manifest_and_error(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); bundle=self.fixture(root)
            argv=['trace_boot.py','--bundle',str(bundle),'--cache',str(root/'cache'),'--out',str(root/'out')]
            read_text=Path.read_text
            def read(path,*args,**kwargs):
                if str(path)=='/proc/sys/kernel/random/boot_id': return 'fixture-boot\n'
                return read_text(path,*args,**kwargs)
            with mock.patch('sys.argv',argv),mock.patch.object(trace_boot.fc,'verify_release'), \
                 mock.patch.object(trace_boot.Path,'read_text',read), \
                 mock.patch.object(trace_boot.fc,'VM',side_effect=RuntimeError('launch failed')):
                with self.assertRaisesRegex(RuntimeError,'launch failed'): trace_boot.main()
            self.assertEqual((root/'out/manifest.json').read_bytes(),(bundle/'manifest.json').read_bytes())
            result=json.loads((root/'out/trace.json').read_text())
            self.assertEqual(result['error'],'launch failed')
            self.assertEqual(result['observations'],[])

if __name__=='__main__': unittest.main()
