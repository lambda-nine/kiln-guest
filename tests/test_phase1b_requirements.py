"""KG-06/KG-07 remain explicit deployment blockers after the re-attack."""
from pathlib import Path
import unittest
class Phase1bTests(unittest.TestCase):
    def test_cold_boot_and_approved_identity_requirements(self):
        readme=(Path(__file__).resolve().parents[1]/'README.md').read_text()
        for text in ['2026-10-30-guest-reattack.md','shares one KASLR layout',
                     'KG-06 is a hard Phase 1b admission requirement',
                     'KG-07 is a hard Phase 1b restore requirement']:
            self.assertIn(text,readme)
