#!/usr/bin/env python3
"""Create scoped K8s secrets without putting credentials in argv or Helm values.

Usage: python3 server/deploy/bootstrap-secrets.py --kubeconfig FILE --smtp-password-file FILE
An existing DB password is NEVER rotated by this script.
"""
import argparse
import json
from pathlib import Path
import secrets
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kubeconfig', required=True)
parser.add_argument('--smtp-password-file', required=True)
args = parser.parse_args()
password = Path(args.smtp_password_file).read_text().strip()
if not password or len(password.splitlines()) != 1:
    raise SystemExit('SMTP password file must contain one nonempty line.')
base = ['kubectl', '--kubeconfig', args.kubeconfig]


def apply(resource):
    result = subprocess.run(base + ['apply', '--server-side', '--field-manager=consolecrypt-deploy', '-f', '-'], input=json.dumps(resource), text=True, capture_output=True)
    if result.returncode:
        raise SystemExit(f'Could not apply {resource["kind"]}/{resource["metadata"]["name"]}; inspect scoped Kubernetes events.')
    print(f'{resource["kind"]}/{resource["metadata"]["name"]}: configured')


apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'consolecrypt', 'labels': {'app.kubernetes.io/part-of': 'consolecrypt'}}})
found = subprocess.run(base + ['-n', 'consolecrypt', 'get', 'secret', 'consolecrypt-database', '--ignore-not-found', '-o', 'name'], capture_output=True, text=True)
if found.returncode:
    raise SystemExit('Could not check existing DB secret; refusing to overwrite it.')
if not found.stdout.strip():
    apply({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'consolecrypt-database', 'namespace': 'consolecrypt'}, 'type': 'Opaque', 'stringData': {'password': secrets.token_urlsafe(36)}})
else:
    print('Secret/consolecrypt-database: preserved')
apply({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'consolecrypt-smtp', 'namespace': 'consolecrypt'}, 'type': 'Opaque', 'stringData': {'smtp-password': password}})
