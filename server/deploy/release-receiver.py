#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Forced SSH command: update only the API using administrator-installed files."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

MAX_PAYLOAD_BYTES = 128 * 1024


def receive(stream, installation=None):
    raw = stream.read(MAX_PAYLOAD_BYTES + 1)
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ValueError('Deployment request exceeds the size limit')
    payload = json.loads(raw)
    if not isinstance(payload, dict) or not {'manifest', 'tag', 'revision'} <= payload.keys():
        raise ValueError('Deployment request is incomplete')
    if payload.keys() - {'manifest', 'tag', 'revision', 'script', 'config'}:
        raise ValueError('Unsupported deployment request fields')
    if not isinstance(payload['manifest'], dict) or not all(isinstance(payload[key], str) for key in ('tag', 'revision')):
        raise ValueError('Invalid deployment manifest')
    if not all(isinstance(payload['manifest'].get(key), str) for key in ('version', 'tag', 'revision', 'image', 'digest', 'source_url')):
        raise ValueError('Invalid deployment manifest fields')
    root = Path(installation) if installation is not None else Path(__file__).resolve().parent
    helper, config = root / 'release-compose.py', root / 'server.json'
    # SSH_ORIGINAL_COMMAND and the sender's script/config cannot select executable
    # code or another service. Only these administrator-owned files are used.
    spec = importlib.util.spec_from_file_location('installed_server_release', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if module.COMPONENT != 'server' or module.REPOSITORY != 'evsikovas/consolecrypt-server':
        raise ValueError('The installed helper must belong to the API server')
    module.validate_manifest(payload['manifest'], payload['tag'], payload['revision'])
    if not config.is_file():
        raise ValueError('Install server.json beside the receiver')
    # The server image is public. No registry credential needs to reach the host.
    with tempfile.TemporaryDirectory(prefix='consolecrypt-server-release-') as directory:
        manifest = Path(directory) / 'image.json'
        manifest.write_text(json.dumps(payload['manifest']))
        manifest.chmod(0o600)
        subprocess.run([sys.executable, str(helper), '--config', str(config),
                        '--manifest', str(manifest), '--tag', payload['tag'],
                        '--revision', payload['revision']], stdin=subprocess.DEVNULL, check=True)


def main():
    try:
        receive(sys.stdin.buffer)
    except Exception:
        print('Server deployment rejected or failed; inspect the release and host state.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
