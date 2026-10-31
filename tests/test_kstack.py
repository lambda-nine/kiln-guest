"""KR-03: default stack-offset randomization is a required resolved symbol."""
import json
from pathlib import Path
import tempfile
import unittest
from kernel_policy import validate
ROOT=Path(__file__).resolve().parents[1]
class KstackTests(unittest.TestCase):
    def test_policy_requires_default_and_rejects_disabled(self):
        self.assertEqual(json.loads((ROOT/'config/security-policy.json').read_text())['required'].get('RANDOMIZE_KSTACK_OFFSET_DEFAULT'),'y')
        with tempfile.TemporaryDirectory() as d:
            config=Path(d)/'config'
            config.write_text((ROOT/'config/kernel.config').read_text().replace('CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=y','# CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT is not set'))
            with self.assertRaises(ValueError): validate(config)
