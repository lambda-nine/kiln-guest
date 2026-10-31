"""Reject duplicate samples, substituted identities and diagnostic acceptance."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
VALIDATION=HERE/'validation' if (HERE/'validation').exists() else HERE/'experiments/first-pass/validation'
spec=importlib.util.spec_from_file_location('aggregate',HERE/'aggregate.py')
a=importlib.util.module_from_spec(spec); spec.loader.exec_module(a)

class AcceptanceTests(unittest.TestCase):
    def test_round_duplicates_and_wrong_warmups_are_rejected(self):
        rows=[json.loads(s) for s in (VALIDATION/'records.jsonl').read_text().splitlines()]
        self.assertEqual(a.stats(rows)['n'],20)
        duplicate=copy.deepcopy(rows); duplicate[3]=copy.deepcopy(duplicate[2])
        with self.assertRaisesRegex(ValueError,'unique'): a.stats(duplicate)
        warmup=copy.deepcopy(rows); warmup[2]['warmup']=True
        with self.assertRaisesRegex(ValueError,'warmup'): a.stats(warmup)

    def test_unrelated_bundle_identity_and_diagnostic_boot_are_rejected(self):
        manifest=(VALIDATION/'manifest.json').read_bytes()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'validation'; shutil.copytree(VALIDATION,root)
            self.assertEqual(a.evidence(root,manifest,'Transparent')['latency_ms']['n'],20)
            c=json.loads((root/'conditions.json').read_text()); c['manifest_sha256']='0'*64
            (root/'conditions.json').write_text(json.dumps(c))
            with self.assertRaisesRegex(ValueError,'manifest'): a.evidence(root,manifest,'Transparent')
            c['manifest_sha256']=a.hashlib.sha256(manifest).hexdigest()
            (root/'conditions.json').write_text(json.dumps(c))
            cfg=json.loads((root/'boot-00.config.json').read_text())
            cfg['boot-source']['boot_args']+=' init_on_free=0 kiln.test=1'
            (root/'boot-00.config.json').write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError,'launch arguments'): a.evidence(root,manifest,'Transparent')
            with self.assertRaisesRegex(ValueError,'archived manifest'): a.evidence(root,b'{}','Transparent')

if __name__=='__main__': unittest.main()
