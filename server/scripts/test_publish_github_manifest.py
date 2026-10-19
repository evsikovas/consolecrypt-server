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
            'GITHUB_REF': 'refs/tags/v0.1.12',
            'GITHUB_EVENT_NAME': 'push',
            'GITHUB_STEP_SUMMARY': str(self.root / 'summary.md'),
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.source = patch.object(publish, 'release_plan', return_value={
            'version': '0.1.12', 'revision': 'c' * 40, 'tag': 'v0.1.12',
            'source_url': 'https://github.com/evsikovas/consolecrypt-server/tree/' + 'c' * 40,
        }).start()
        self.absent = patch.object(publish, 'require_absent').start()
        self.run = patch.object(publish.subprocess, 'run').start()
        self.inspect = patch.object(publish.subprocess, 'check_output',
                                    return_value=json.dumps({'digest': 'sha256:' + 'd' * 64})).start()
        self.addCleanup(patch.stopall)

    def report(self):
        publish.main()
        return json.loads((self.root / 'dist/server-image.json').read_text())

    def test_release_publishes_verified_digests_without_mutable_latest(self):
        report = self.report()
        self.assertTrue(report['release'])
        self.assertEqual(report['tag'], 'v0.1.12')
        self.assertEqual(report['tags'], [self.image + ':sha-' + 'c' * 40, self.image + ':0.1.12'])
        self.assertEqual(report['revision'], 'c' * 40)
        self.assertEqual(report['image'], self.image + '@sha256:' + 'd' * 64)
        command = self.run.call_args.args[0]
        self.assertEqual(command[-2:], [self.image + '@sha256:' + char * 64 for char in ('a', 'b')])
        self.assertEqual(self.absent.call_count, 2)

    def test_invalid_source_cannot_publish(self):
        self.source.side_effect = ValueError('not a matching tag from main')
        with self.assertRaises(ValueError):
            publish.main()
        self.run.assert_not_called()

    def test_existing_release_is_not_overwritten(self):
        self.absent.side_effect = ValueError('already published')
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
