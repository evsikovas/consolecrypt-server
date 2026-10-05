# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import publish_github_manifest as publish


class GitHubPublicationGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        old_directory = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, old_directory)
        (self.root / 'server').mkdir()
        (self.root / 'server/Cargo.toml').write_text('[package]\nversion = "0.1.12"\n')
        (self.root / 'dist/digests').mkdir(parents=True)
        self.image = 'ghcr.io/evsikovas/consolecrypt-server'
        for arch, digest in [('amd64', 'a'), ('arm64', 'b')]:
            (self.root / f'dist/digests/{arch}').write_text(self.image + '@sha256:' + digest * 64)
        self.environment = patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'evsikovas/consolecrypt-server',
            'GITHUB_SHA': 'c' * 40,
            'GITHUB_REF': 'refs/heads/main',
            'GITHUB_STEP_SUMMARY': str(self.root / 'summary.md'),
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.run = patch.object(publish.subprocess, 'run').start()
        self.inspect = patch.object(publish.subprocess, 'check_output',
                                    return_value=json.dumps({'digest': 'sha256:' + 'd' * 64})).start()
        self.addCleanup(patch.stopall)

    def report(self):
        publish.main()
        return json.loads((self.root / 'dist/server-image.json').read_text())

    def test_main_does_not_move_stable_aliases(self):
        report = self.report()
        self.assertFalse(report['release'])
        self.assertEqual(len(report['tags']), 2)
        self.assertEqual(report['revision'], 'c' * 40)
        self.assertEqual(report['image'], self.image + '@sha256:' + 'd' * 64)
        command = self.run.call_args.args[0]
        self.assertEqual(command[-2:], [self.image + '@sha256:' + char * 64 for char in ('a', 'b')])

    def test_matching_release_tag_adds_stable_aliases(self):
        with patch.dict(os.environ, {'GITHUB_REF': 'refs/tags/server-v0.1.12'}):
            report = self.report()
        self.assertTrue(report['release'])
        self.assertIn(self.image + ':0.1.12', report['tags'])
        self.assertIn(self.image + ':latest', report['tags'])

    def test_untrusted_ref_or_repository_cannot_publish(self):
        for environment in [
            {'GITHUB_REF': 'refs/heads/feature'},
            {'GITHUB_REF': 'refs/pull/1/merge'},
            {'GITHUB_REF': 'refs/tags/server-v0.1.11'},
            {'GITHUB_REPOSITORY': 'other/server'},
            {'GITHUB_SHA': 'HEAD'},
        ]:
            with self.subTest(environment=environment), patch.dict(os.environ, environment):
                with self.assertRaises(ValueError):
                    publish.main()
        self.run.assert_not_called()

    def test_missing_architecture_cannot_publish(self):
        (self.root / 'dist/digests/arm64').unlink()
        with self.assertRaises(FileNotFoundError):
            publish.main()
        self.run.assert_not_called()

    def test_only_expected_repository_digests_are_accepted(self):
        for value in ['ghcr.io/other/server@sha256:' + 'a' * 64,
                      self.image + ':latest', '--tag other/server:latest']:
            with self.subTest(value=value):
                (self.root / 'dist/digests/amd64').write_text(value)
                with self.assertRaises(ValueError):
                    publish.main()
        self.run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
