"""Daybreak B1 PoCs and the cross-language conformance contract."""
import copy
import inspect
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from b1_conformance import case_bytes, validate
import phase1b_contract as p1
import phase1b_fixture as f1

ROOT=Path(__file__).resolve().parent/'fixtures/firecracker'

class B1ConformanceTests(unittest.TestCase):
    def test_shared_conformance_corpus(self):
        corpus=json.loads((ROOT/'conformance.json').read_text())
        self.assertGreater(len(corpus['cases']),2000)
        for case in corpus['cases']:
            with self.subTest(case=case['name']):
                raw=case_bytes(case,corpus['bases'])
                if not case['accept']:
                    with self.assertRaises(ValueError): validate(case['kind'],raw,corpus['bases'])
                else:
                    actual=validate(case['kind'],raw,corpus['bases'])
                    self.assertEqual(actual,case['canonical_ascii'].encode('ascii'))
                    self.assertEqual(p1.digest(actual),case['sha256'])

    def test_unicode_and_duplicate_poc(self):
        self.assertEqual(p1.canonical(p1.strict_json('{"writable_paths":["/雪"]}'.encode())),
                         b'{"writable_paths":["/\\u96ea"]}')
        with self.assertRaises(ValueError): p1.strict_json(b'{"schema":1,"schema":2}')

    def test_label_collision_and_journal_replay(self):
        spec=json.loads((ROOT/'substitutions.json').read_text())['inner_spec']
        a=p1.spec_binding({**spec,'labels':{'tenant':'alpha'}})
        b=p1.spec_binding({**spec,'labels':{'tenant':'beta'}})
        self.assertNotEqual(a['host_spec_sha256'],b['host_spec_sha256'])
        self.assertEqual(a['guest_exec_spec_sha256'],b['guest_exec_spec_sha256'])
        raw=(ROOT/'bundle/manifest.json').read_bytes()
        subs=json.loads((ROOT/'substitutions.json').read_text())
        pa=f1.plan(raw,p1.digest(raw),subs,{'tenant':'alpha'}).document
        pb=f1.plan(raw,p1.digest(raw),subs,{'tenant':'beta'}).document
        self.assertNotEqual(p1.plan_digest(pa),p1.plan_digest(pb))
        self.assertEqual(p1.identity_block(pa),p1.identity_block(pb))

    def test_fixture_mode_poc_cannot_make_production_plan(self):
        raw=(ROOT/'bundle/manifest.json').read_bytes(); approved=p1.digest(raw)
        subs=json.loads((ROOT/'substitutions.json').read_text())
        fixture=f1.plan(raw,approved,subs)
        self.assertIsInstance(fixture,f1.FixturePlan)
        self.assertEqual(fixture.document['profile'],'test-only-b1')
        self.assertNotEqual(fixture.document['schema'],2)
        for fn in [p1.verify_manifest,p1.verify_bundle,p1.plan,p1.verify_plan]:
            self.assertNotIn('fixture_only',inspect.signature(fn).parameters)
        for schema in [f1.FIXTURE_MANIFEST_SCHEMA,2]:
            for flag in [True,False]:
                manifest=json.loads(raw); manifest.update(schema=schema,fixture_only=flag)
                encoded=p1.canonical(manifest)
                with self.assertRaises(ValueError): p1.plan(encoded,p1.digest(encoded),subs)
        with self.assertRaises(TypeError): p1.plan(raw,approved,subs,fixture_only=True)
        self.assertNotIn('phase1b_fixture', (ROOT.parents[2]/'scripts/phase1b_contract.py').read_text())

    def test_canonical_rejects_constructed_float_and_deep_values(self):
        for v in [1.0,2**64,-2**63-1,{1:'x'},'\ud800']:
            with self.assertRaises(ValueError): p1.canonical(v)
        value=0
        for _ in range(33): value=[value]
        with self.assertRaises(ValueError): p1.canonical(value)
