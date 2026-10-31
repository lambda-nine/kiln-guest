"""KR-04: UID output policy must be installed before DNS starts."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class DNSEgressTests(unittest.TestCase):
    def test_filter_precedes_daemon(self):
        init=(ROOT/'src/init.c').read_text()
        self.assertLess(init.index('install_dns_egress();'),init.index('dns_pid = start_dns'))
        rules=(ROOT/'src/dns_egress.h').read_text()
        for text in ['meta skuid 65532','ct direction reply','ct state established',
                     'ip daddr 1.1.1.1','th dport 53','th sport 53','counter reject',
                     'dns-private-egress-denied','dns-other-resolver-denied',
                     'dns-upstream-wrong-port-denied','dns-upstream-query-allowed']:
            self.assertIn(text,rules)
