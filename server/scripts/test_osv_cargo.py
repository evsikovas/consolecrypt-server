"""Security gate regressions with synthetic registries; no live network."""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

import osv_cargo


class OsvCargoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'Cargo.toml').write_text('[package]\nname="test"\nversion="1.0.0"\n[dependencies]\npublic="1"\n')
        (self.root / 'Cargo.lock').write_text(
            'version=4\n[[package]]\nname="public"\nversion="1.0.0"\n'
            'source="registry+https://github.com/rust-lang/crates.io-index"\n'
            '[[package]]\nname="private"\nversion="1.0.0"\nsource="registry+https://private.invalid/index"\n')

    def request(self, informational=None, withdrawn=False):
        def request(path, payload=None):
            if path == 'querybatch':
                self.assertEqual([q['package']['name'] for q in payload['queries']], ['public'])
                return {'results': [{'vulns': [{'id': 'GHSA-example'}]}]}
            return {'summary': 'test advisory', 'withdrawn': '2026-01-01' if withdrawn else None,
                    'affected': [{'package': {'name': 'public'}, 'database_specific': {'informational': informational}}]}
        return request

    def check(self, request):
        return osv_cargo.check(self.root, ['Cargo.toml'], request=request, today=dt.date(2026, 11, 4))

    def test_ghsa_only_advisory_blocks_and_private_registry_is_never_submitted(self):
        findings = self.check(self.request())
        self.assertEqual(findings[0]['id'], 'GHSA-example')
        self.assertEqual(findings[0]['package'], 'public@1.0.0')

    def test_direct_unmaintained_blocks_and_transitive_is_reported(self):
        self.assertEqual(len(self.check(self.request('unmaintained'))), 1)
        (self.root / 'Cargo.toml').write_text('[package]\nname="test"\nversion="1.0.0"\n')
        self.assertEqual(self.check(self.request('unmaintained')), [])

    def test_unsound_is_not_treated_as_unmaintained(self):
        (self.root / 'Cargo.toml').write_text('[package]\nname="test"\nversion="1.0.0"\n')
        self.assertEqual(len(self.check(self.request('unsound'))), 1)

    def test_withdrawn_advisory_does_not_block(self):
        self.assertEqual(self.check(self.request(withdrawn=True)), [])

    def test_incomplete_response_fails_closed(self):
        with self.assertRaises(ValueError):
            self.check(lambda *_: {'results': []})

    def test_expired_exception_fails_closed(self):
        (self.root / 'security-exceptions.toml').write_text(
            '[[exception]]\nid="GHSA-example"\npackage="public"\n'
            'owner="maintainer"\nreason="test"\nexpires="2026-11-03"\n')
        with self.assertRaises(ValueError):
            self.check(self.request())

    def test_valid_exception_is_package_bound(self):
        policy = ('[[exception]]\nid="GHSA-example"\npackage="public"\n'
                  'owner="maintainer"\nreason="test"\nexpires="2027-01-01"\n')
        (self.root / 'security-exceptions.toml').write_text(policy)
        self.assertEqual(self.check(self.request()), [])
        (self.root / 'security-exceptions.toml').write_text(policy.replace('package="public"', 'package="wrong"'))
        with self.assertRaises(ValueError):
            self.check(self.request())


if __name__ == '__main__':
    unittest.main()
