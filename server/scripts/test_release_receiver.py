# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

DEPLOY = Path(__file__).resolve().parents[1] / 'deploy'
SPEC = importlib.util.spec_from_file_location('server_receiver', DEPLOY / 'release-receiver.py')
receiver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receiver)


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        shutil.copyfile(DEPLOY / 'release-compose.py', self.root / 'release-compose.py')
        (self.root / 'server.json').write_text('{}')
        self.payload = {
            'tag': 'v1.2.3', 'revision': 'a' * 40,
            'manifest': {'version': '1.2.3', 'tag': 'v1.2.3', 'revision': 'a' * 40,
                         'source_url': 'https://github.com/evsikovas/consolecrypt-server/tree/' + 'a' * 40,
                         'image': 'ghcr.io/evsikovas/consolecrypt-server@sha256:' + 'b' * 64,
                         'digest': 'sha256:' + 'b' * 64, 'release': True},
            'script': "raise Exception('untrusted script was executed')", 'config': '/other/service.json',
        }

    def stream(self, payload=None):
        return io.BytesIO(json.dumps(self.payload if payload is None else payload).encode())

    def test_only_installed_code_config_and_validated_manifest_reach_deployer(self):
        manifests = []
        def invoke(command, **kwargs):
            self.assertEqual(command[1], str(self.root / 'release-compose.py'))
            self.assertEqual(command[command.index('--config') + 1], str(self.root / 'server.json'))
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            manifest = Path(command[command.index('--manifest') + 1])
            self.assertEqual(json.loads(manifest.read_text()), self.payload['manifest'])
            self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
            manifests.append(manifest)
        with patch.dict(os.environ, {'SSH_ORIGINAL_COMMAND': 'echo untrusted'}), \
             patch.object(receiver.subprocess, 'run', side_effect=invoke) as run:
            receiver.receive(self.stream(), self.root)
        run.assert_called_once()
        self.assertFalse(manifests[0].exists())

    def test_wrong_component_mutable_digest_source_and_payload_are_rejected(self):
        reports = [dict(self.payload['manifest'], image='ghcr.io/evsikovas/consolecrypt-server:1.2.3'),
                   dict(self.payload['manifest'], image='ghcr.io/evsikovas/consolecrypt-site@sha256:' + 'b' * 64),
                   dict(self.payload['manifest'], digest='sha256:' + 'c' * 64),
                   dict(self.payload['manifest'], source_url='https://github.com/other/repo/tree/' + 'a' * 40),
                   dict(self.payload['manifest'], version='1.2.4'), dict(self.payload['manifest'], release=False)]
        invalid = [dict(self.payload, manifest=report) for report in reports]
        invalid += [dict(self.payload, manifest=[]), dict(self.payload, revision=[]),
                    dict(self.payload, operation='rollback'), dict(self.payload, registry={'token': 'unneeded'})]
        with patch.object(receiver.subprocess, 'run') as run:
            for payload in invalid:
                with self.subTest(payload=payload), self.assertRaises(ValueError):
                    receiver.receive(self.stream(payload), self.root)
            run.assert_not_called()

    def test_payload_read_is_bounded(self):
        class BoundedStream:
            def read(self, size):
                self.size = size
                return b'x' * size
        stream = BoundedStream()
        with self.assertRaises(ValueError):
            receiver.receive(stream, self.root)
        self.assertEqual(stream.size, receiver.MAX_PAYLOAD_BYTES + 1)


if __name__ == '__main__':
    unittest.main()
