# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import deploy_ssh
import publish_release


class ReleaseDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        before = Path.cwd()
        os.chdir(self.directory.name)
        self.addCleanup(os.chdir, before)
        Path('dist').mkdir()
        self.plan = {'version': '1.2.3', 'revision': 'a' * 40, 'tag': 'v1.2.3',
                     'source_url': f'https://github.com/{publish_release.REPOSITORY}/tree/' + 'a' * 40}
        self.report = dict(self.plan, image=publish_release.IMAGE + '@sha256:' + 'b' * 64,
                           digest='sha256:' + 'b' * 64, release=True)
        self.manifest = Path(f'dist/{publish_release.COMPONENT}-image.json')
        self.manifest.write_text(json.dumps(self.report))
        self.env = patch.dict(os.environ, {'GITHUB_RUN_ID': '12345', 'GITHUB_RUN_ATTEMPT': '2',
                                          'PROD_SSH_HOST': 'production.example.invalid', 'PROD_SSH_USER': 'deployer',
                                          'PROD_DEPLOY_CONFIG_PATH': '/etc/consolecrypt/release.json',
                                          'PROD_SSH_PRIVATE_KEY': 'private-key-do-not-print',
                                          'PROD_SSH_KNOWN_HOSTS': 'verified-host-key'}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        for module in (publish_release, deploy_ssh):
            mock = patch.object(module, 'release_plan', return_value=self.plan)
            mock.start()
            self.addCleanup(mock.stop)

    def draft(self, *args, **kwargs):
        assets = [self.manifest, Path('dist/build-receipt.json'), Path('dist/SHA256SUMS')]
        return json.dumps({'isDraft': True, 'targetCommitish': self.plan['revision'],
                           'assets': [{'name': path.name, 'size': path.stat().st_size} for path in assets]})

    def test_receipts_uploaded_to_draft_before_one_time_publication(self):
        with patch.object(publish_release.subprocess, 'run') as run, \
             patch.object(publish_release.subprocess, 'check_output', side_effect=self.draft):
            publish_release.main()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn('--draft', commands[0])
        self.assertIn('--verify-tag', commands[0])
        self.assertIn('--draft=false', commands[1])
        self.assertFalse(any('--clobber' in command for command in commands))
        for line in Path('dist/SHA256SUMS').read_text().splitlines():
            digest, filename = line.split('  ')
            self.assertEqual(digest, hashlib.sha256(Path('dist', filename).read_bytes()).hexdigest())
        receipt = json.loads(Path('dist/build-receipt.json').read_text())
        self.assertEqual(receipt['workflow_run_attempt'], 2)
        self.assertEqual(receipt['image'], self.report['image'])

    def test_existing_release_or_wrong_assets_cannot_be_modified_or_published(self):
        with patch.object(publish_release.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'gh')) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                publish_release.main()
            self.assertEqual(run.call_count, 1)
        with patch.object(publish_release.subprocess, 'run') as run, \
             patch.object(publish_release.subprocess, 'check_output', return_value=json.dumps({
                 'isDraft': True, 'targetCommitish': self.plan['revision'], 'assets': []})):
            with self.assertRaises(ValueError):
                publish_release.main()
            self.assertEqual(run.call_count, 1)

    def test_ssh_pins_host_key_and_keeps_private_key_out_of_command_and_payload(self):
        def ssh(command, **kwargs):
            self.assertIn('StrictHostKeyChecking=yes', command)
            self.assertIn('BatchMode=yes', command)
            self.assertIn('ForwardAgent=no', command)
            key_path = Path(command[command.index('-i') + 1])
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(key_path.read_text().strip(), 'private-key-do-not-print')
            self.assertNotIn('private-key-do-not-print', ' '.join(command) + kwargs['input'])
            payload = json.loads(kwargs['input'])
            self.assertEqual(payload['manifest'], self.report)
            self.assertEqual(payload['tag'], self.plan['tag'])
            self.assertEqual(payload['config'], '/etc/consolecrypt/release.json')
        with patch.object(deploy_ssh.subprocess, 'run', side_effect=ssh) as run:
            deploy_ssh.main()
            self.assertEqual(run.call_count, 1)

    def test_invalid_ssh_destination_and_manifest_fail_before_connection(self):
        with patch.object(deploy_ssh.subprocess, 'run') as run:
            with patch.dict(os.environ, {'PROD_SSH_HOST': 'host;unsafe'}):
                with self.assertRaises(ValueError):
                    deploy_ssh.main()
            self.manifest.write_text(json.dumps(dict(self.report, revision='f' * 40)))
            with self.assertRaises(ValueError):
                deploy_ssh.main()
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
