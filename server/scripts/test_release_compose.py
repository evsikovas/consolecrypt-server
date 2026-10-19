# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('release_compose', Path(__file__).resolve().parents[1] / 'deploy/release-compose.py')
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class ComposeReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = {'project_directory': str(self.root), 'state_directory': str(self.root / 'state'),
                       'env_file': str(self.root / 'private.env'), 'compose_files': [str(self.root / 'compose.yml')],
                       'project': 'production', 'service': deploy.COMPONENT, 'base_url': 'https://example.invalid'}
        self.report = {'version': '1.2.3', 'revision': 'a' * 40, 'tag': 'v1.2.3', 'release': True,
                       'source_url': f'https://github.com/{deploy.REPOSITORY}/tree/' + 'a' * 40,
                       'image': deploy.IMAGE + '@sha256:' + 'b' * 64, 'digest': 'sha256:' + 'b' * 64}
        self.old_id = 'sha256:' + 'c' * 64
        self.new_id = 'sha256:' + 'd' * 64
        self.running_id = self.old_id
        self.commands = []
        self.fail_up = False
        self.process = patch.object(deploy, 'run', side_effect=self.command)
        self.process.start()
        self.addCleanup(self.process.stop)
        self.health = patch.object(deploy, 'probe')
        self.health.start()
        self.addCleanup(self.health.stop)

    def command(self, *args):
        self.commands.append(args)
        if 'ps' in args:
            return 'f' * 64
        if args[1:3] == ('inspect', 'f' * 64):
            if '{{.Image}}' in args:
                return self.running_id
            return json.dumps(['PRIVATE_PASSWORD=never-record-this', 'CC_SOURCE_CODE_URL=https://example.invalid/old-source'])
        if args[1:3] == ('image', 'inspect'):
            return self.old_id if args[3] == self.old_id else self.new_id
        if 'up' in args:
            if self.fail_up:
                raise RuntimeError('rollout failed')
            current = json.loads((self.root / 'state/compose.release.json').read_text())
            self.running_id = self.old_id if current['services'][deploy.COMPONENT]['image'] == self.old_id else self.new_id
        return ''

    def test_manifest_requires_matching_tag_source_and_digest(self):
        self.assertEqual(deploy.validate_manifest(self.report, 'v1.2.3', 'a' * 40), self.report)
        for fields in ({'image': deploy.IMAGE + ':latest'}, {'digest': 'sha256:' + 'e' * 64},
                       {'source_url': 'https://example.invalid/other'}, {'tag': 'server-v1.2.3'},
                       {'release': False}, {'revision': 'f' * 40}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                deploy.validate_manifest(dict(self.report, **fields), 'v1.2.3', 'a' * 40)
        self.assertEqual(self.commands, [])

    def test_deploy_only_updates_one_existing_service_and_retains_exact_rollback(self):
        deploy.deploy(self.config, self.report)
        state = self.root / 'state'
        override = json.loads((state / 'compose.release.json').read_text())
        self.assertEqual(list(override['services']), [deploy.COMPONENT])
        self.assertEqual(override['services'][deploy.COMPONENT]['image'], self.report['image'])
        self.assertEqual(json.loads((state / 'previous.json').read_text())['image_id'], self.old_id)
        self.assertNotIn('never-record-this', (state / 'previous.json').read_text())
        command = next(args for args in self.commands if 'up' in args)
        for flag in ('--no-deps', '--no-build', '--wait'):
            self.assertIn(flag, command)
        self.assertEqual(command[-1], deploy.COMPONENT)
        self.assertFalse((state / 'pending.json').exists())
        self.commands.clear()
        deploy.deploy(self.config, rollback=True)
        self.assertEqual(self.running_id, self.old_id)
        self.assertFalse(any('pull' in args for args in self.commands))

    def test_failed_deploy_keeps_original_snapshot_across_retry(self):
        self.fail_up = True
        with self.assertRaises(RuntimeError):
            deploy.deploy(self.config, self.report)
        previous = (self.root / 'state/previous.json').read_bytes()
        self.running_id = self.new_id  # A partial rollout may already have replaced the container.
        self.fail_up = False
        deploy.deploy(self.config, self.report)
        self.assertEqual((self.root / 'state/previous.json').read_bytes(), previous)

    def test_different_release_cannot_replace_a_pending_rollback_snapshot(self):
        self.fail_up = True
        with self.assertRaises(RuntimeError):
            deploy.deploy(self.config, self.report)
        previous = (self.root / 'state/previous.json').read_bytes()
        with self.assertRaises(ValueError):
            deploy.deploy(self.config, dict(self.report, version='1.2.4'))
        self.assertEqual((self.root / 'state/previous.json').read_bytes(), previous)


if __name__ == '__main__':
    unittest.main()
