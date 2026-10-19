# SPDX-License-Identifier: AGPL-3.0-only
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import release


class ReleaseSourceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        before = Path.cwd()
        os.chdir(self.directory.name)
        self.addCleanup(os.chdir, before)
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Release Test')
        Path('server').mkdir()
        Path('server/Cargo.toml').write_text('[package]\nversion = "0.1.12"\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'release')
        self.sha = self.git('rev-parse', 'HEAD')
        self.git('update-ref', 'refs/remotes/origin/main', self.sha)
        self.git('tag', '-a', 'v0.1.12', '-m', 'release')
        self.env = {'GITHUB_REPOSITORY': release.REPOSITORY, 'GITHUB_EVENT_NAME': 'push',
                    'GITHUB_REF': 'refs/tags/v0.1.12', 'GITHUB_SHA': self.sha}

    @staticmethod
    def git(*args):
        return subprocess.check_output(['git', *args], text=True, stderr=subprocess.DEVNULL).strip()

    def test_annotated_tag_on_main(self):
        self.assertEqual(release.release_plan(self.env)['revision'], self.sha)

    def test_main_pull_request_old_prefix_wrong_version_or_repository_rejected(self):
        for values in ({'GITHUB_REF': 'refs/heads/main'}, {'GITHUB_EVENT_NAME': 'pull_request'},
                       {'GITHUB_EVENT_NAME': 'workflow_dispatch'},
                       {'GITHUB_REF': 'refs/tags/server-v0.1.12'}, {'GITHUB_REF': 'refs/tags/v0.1.11'},
                       {'GITHUB_REPOSITORY': 'other/server'}, {'GITHUB_SHA': 'f' * 40}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                release.release_plan(dict(self.env, **values))

    def test_tag_on_unmerged_branch_is_rejected(self):
        self.git('checkout', '-qb', 'unmerged')
        Path('code').write_text('new code')
        self.git('add', '.')
        self.git('commit', '-qm', 'unmerged')
        self.git('tag', '-d', 'v0.1.12')
        self.git('tag', 'v0.1.12')
        with self.assertRaises(subprocess.CalledProcessError):
            release.release_plan(dict(self.env, GITHUB_SHA=self.git('rev-parse', 'HEAD')))

    def test_tag_moved_from_checkout_or_dirty_checkout_is_rejected(self):
        Path('server/Cargo.toml').write_text('[package]\nversion = "0.1.12"\n# dirty\n')
        with self.assertRaises(ValueError):
            release.release_plan(self.env)
        self.git('add', '.')
        self.git('commit', '-qm', 'different checkout')
        with self.assertRaises(ValueError):
            release.release_plan(dict(self.env, GITHUB_SHA=self.git('rev-parse', 'HEAD')))


class RegistryGuardTests(unittest.TestCase):
    def test_only_confirmed_missing_tag_allows_publication(self):
        for status, error, allowed in ((1, 'manifest unknown', True), (1, 'ghcr.io/example/image:1.0.0: not found', True),
                                       (0, '', False), (1, 'unauthorized', False), (1, 'timeout', False), (1, 'host not found', False)):
            with self.subTest(error=error), patch.object(release.subprocess, 'run',
                                                       return_value=SimpleNamespace(returncode=status, stderr=error)):
                if allowed:
                    release.require_absent('ghcr.io/example/image:1.0.0')
                else:
                    with self.assertRaises((ValueError, RuntimeError)):
                        release.require_absent('ghcr.io/example/image:1.0.0')


if __name__ == '__main__':
    unittest.main()
