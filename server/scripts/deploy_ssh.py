#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Deliver a validated tagged digest to the existing host; never accept an unknown SSH host key."""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

from release import release_plan

COMPONENT = 'server'
REMOTE = '''import json, pathlib, subprocess, sys, tempfile
payload = json.load(sys.stdin)
with tempfile.TemporaryDirectory(prefix="consolecrypt-release-") as directory:
    root = pathlib.Path(directory)
    script = root / "release-compose.py"
    script.write_text(payload["script"])
    manifest = root / "image.json"
    manifest.write_text(json.dumps(payload["manifest"]))
    subprocess.run([sys.executable, str(script), "--config", payload["config"],
                    "--manifest", str(manifest), "--tag", payload["tag"],
                    "--revision", payload["revision"]], check=True)
'''


def main():
    plan = release_plan()
    report = json.loads(Path(f'dist/{COMPONENT}-image.json').read_text())
    if any(report.get(key) != plan[key] for key in ('version', 'revision', 'tag', 'source_url')):
        raise ValueError('Deployment manifest differs from the release tag')
    host = os.environ['PROD_SSH_HOST']
    user = os.environ['PROD_SSH_USER']
    port = os.environ.get('PROD_SSH_PORT') or '22'
    config = os.environ['PROD_DEPLOY_CONFIG_PATH']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]*', host) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', user):
        raise ValueError('Invalid SSH host/user')
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('Invalid SSH port')
    if not Path(config).is_absolute() or '\n' in config or '\0' in config:
        raise ValueError('Production config must be an absolute path on the existing host')
    key = os.environ['PROD_SSH_PRIVATE_KEY']
    hosts = os.environ['PROD_SSH_KNOWN_HOSTS']
    if not key.strip() or not hosts.strip():
        raise ValueError('SSH private key and verified known_hosts are required')
    payload = {'script': (Path(__file__).resolve().parents[1] / 'deploy/release-compose.py').read_text(),
               'manifest': report, 'config': config, 'tag': plan['tag'], 'revision': plan['revision']}
    with tempfile.TemporaryDirectory(prefix='consolecrypt-ssh-') as directory:
        identity = Path(directory, 'identity')
        known_hosts = Path(directory, 'known_hosts')
        identity.write_text(key.rstrip() + '\n')
        identity.chmod(0o600)
        known_hosts.write_text(hosts.rstrip() + '\n')
        known_hosts.chmod(0o600)
        subprocess.run(['ssh', '-i', str(identity), '-p', port, '-o', 'BatchMode=yes',
                        '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                        '-o', f'UserKnownHostsFile={known_hosts}', '-o', 'ForwardAgent=no',
                        '-o', 'PasswordAuthentication=no', '-o', 'ClearAllForwardings=yes',
                        '-o', 'ConnectTimeout=20', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
                        '--', f'{user}@{host}', shlex.join(['python3', '-c', REMOTE])],
                       input=json.dumps(payload), text=True, check=True)


if __name__ == '__main__':
    main()
