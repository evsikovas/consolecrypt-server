#!/usr/bin/env python3
"""Preload a local image on one k3s node without changing its registry config.

K3s watches its agent/images directory. A temporary pod mounts ONLY this
directory (not the container runtime socket or host root) and atomically
publishes an image archive. It is always removed afterwards. Requires cluster
administrator access. Run separately for every eligible node in multi-node clusters.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kubeconfig', required=True)
parser.add_argument('--node', required=True)
parser.add_argument('--image', required=True)
parser.add_argument('--archive-name', required=True)
args = parser.parse_args()
if not re.fullmatch(r'consolecrypt-[a-zA-Z0-9_.-]+\.tar', args.archive_name):
    raise SystemExit('Use a safe consolecrypt-*.tar archive name.')
base = ['kubectl', '--kubeconfig', args.kubeconfig, '-n', 'consolecrypt']
name = 'consolecrypt-image-import-' + uuid.uuid4().hex[:8]
pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': 'consolecrypt', 'labels': {'app.kubernetes.io/component': 'image-import'}}, 'spec': {
    'nodeName': args.node, 'restartPolicy': 'Never', 'activeDeadlineSeconds': 900, 'automountServiceAccountToken': False,
    'securityContext': {'seccompProfile': {'type': 'RuntimeDefault'}},
    'containers': [{'name': 'import', 'image': 'alpine:3.22', 'command': ['sleep', '900'], 'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                    'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'memory': '64Mi'}}, 'volumeMounts': [{'name': 'images', 'mountPath': '/images'}]}],
    'volumes': [{'name': 'images', 'hostPath': {'path': '/var/lib/rancher/k3s/agent/images', 'type': 'DirectoryOrCreate'}}]}}
with tempfile.TemporaryDirectory(prefix='consolecrypt-image-') as temp:
    archive = Path(temp) / args.archive_name
    subprocess.run(['docker', 'save', '--output', str(archive), args.image], check=True)
    subprocess.run(base + ['create', '-f', '-'], input=json.dumps(pod), text=True, check=True)
    try:
        subprocess.run(base + ['wait', '--for=condition=Ready', 'pod/' + name, '--timeout=90s'], check=True)
        # The validated name cannot inject shell metacharacters. Only our
        # archive is written; unrelated node image archives are untouched.
        command = f'umask 077; cat > /images/.{args.archive_name}.partial && mv /images/.{args.archive_name}.partial /images/{args.archive_name}'
        with archive.open('rb') as stream:
            subprocess.run(base + ['exec', '-i', name, '--', 'sh', '-ec', command], stdin=stream, check=True)
        print('Image archive delivered atomically. Verify the deployment imageID before serving traffic.')
    finally:
        subprocess.run(base + ['delete', 'pod', name, '--wait=false'], check=False)
