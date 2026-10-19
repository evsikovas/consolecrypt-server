#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Update one existing Compose service by a verified release digest; retain an exact rollback."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

COMPONENT = 'server'
REPOSITORY = f'evsikovas/consolecrypt-{COMPONENT}'
IMAGE = f'ghcr.io/{REPOSITORY}'
SEMVER = r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'


def run(*command):
    # Capture Compose output: configuration interpolation errors can contain secrets.
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'{command[0]} operation failed (exit {result.returncode}); inspect it on the host')
    return result.stdout.strip()


def validate_manifest(report, tag, revision):
    version = report.get('version', '')
    if not re.fullmatch(SEMVER, version) or tag != f'v{version}' or report.get('tag') != tag:
        raise ValueError('Manifest and requested vX.Y.Z tag must match')
    if not re.fullmatch(r'[0-9a-f]{40}', revision) or report.get('revision') != revision:
        raise ValueError('Manifest and requested source commit must match')
    source = f'https://github.com/{REPOSITORY}/tree/{revision}'
    if report.get('release') is not True or report.get('source_url') != source:
        raise ValueError('Expected a release with its exact upstream source URL')
    image = report.get('image', '')
    if not re.fullmatch(re.escape(IMAGE) + r'@sha256:[0-9a-f]{64}', image):
        raise ValueError('Deployment requires an immutable digest in the component registry')
    if report.get('digest') != image.split('@')[1]:
        raise ValueError('Manifest digest fields disagree')
    return report


def compose_command(config):
    for key in ('project_directory', 'state_directory', 'env_file'):
        if not Path(config[key]).is_absolute():
            raise ValueError(f'{key} must be an absolute host path')
    if not config['compose_files'] or any(not Path(path).is_absolute() for path in config['compose_files']):
        raise ValueError('compose_files must contain absolute host paths')
    for key in ('project', 'service'):
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', config[key]):
            raise ValueError(f'Invalid Compose {key}')
    url = urllib.parse.urlsplit(config['base_url'])
    if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('base_url must be a plain HTTP(S) origin/path without credentials')
    result = ['docker', 'compose', '--project-directory', config['project_directory'],
              '--project-name', config['project'], '--env-file', config['env_file']]
    for path in config['compose_files']:
        result += ['--file', path]
    return result


def atomic_json(path, value):
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix='.release-')
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def override(service, image, source=None):
    values = {'image': image, 'pull_policy': 'never'}
    if COMPONENT == 'server' and source is not None:
        values['environment'] = {'CC_SOURCE_CODE_URL': source}
    return {'services': {service: values}}


def probe(config, report):
    base = config['base_url'].rstrip('/')
    health = '/readyz' if COMPONENT == 'server' else '/site-healthz'
    with urllib.request.urlopen(base + health, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError('Service health check failed')
    if not report:  # Historical rollback snapshot may predate release manifests.
        return
    route = '/v1/meta' if COMPONENT == 'server' else '/assets/version.js'
    with urllib.request.urlopen(base + route, timeout=5) as response:
        body = response.read(1024 * 1024).decode()
    if COMPONENT == 'server':
        meta = json.loads(body)
        if meta['server_version'] != report['version'] or meta['source_code_url'] != report['source_url']:
            raise RuntimeError('Public API does not match the release version/source')
    elif body != f'export const VERSION = {json.dumps(report["version"])};\n':
        raise RuntimeError('Public website does not match the release version')


def deploy(config, report=None, rollback=False):
    base = compose_command(config)
    state = Path(config['state_directory'])
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = state / 'compose.release.json'
        previous = state / 'previous.json'
        pending = state / 'pending.json'
        service = config['service']
        if rollback:
            snapshot = json.loads(previous.read_text())
            if snapshot['component'] != COMPONENT or snapshot['project'] != config['project'] or snapshot['service'] != service:
                raise ValueError('Rollback snapshot belongs to a different deployment')
            old_image = snapshot['image_id']
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', old_image):
                raise ValueError('Rollback requires the exact retained local image ID')
            # Do not pull or rebuild: retain the previous local image until validation succeeds.
            run('docker', 'image', 'inspect', old_image, '--format', '{{.Id}}')
            desired = override(service, old_image, snapshot.get('source_url'))
            report = snapshot.get('report')
        else:
            if report is None:
                raise ValueError('A validated release manifest is required')
            if pending.exists() and json.loads(pending.read_text()) != report:
                raise ValueError('Resolve the pending release or roll it back before deploying another release')
            container = run(*base, 'ps', '-q', service)
            if not re.fullmatch(r'[0-9a-f]{12,64}', container):
                raise ValueError('Expected exactly one existing container; bootstrap is a separate operation')
            image_id = run('docker', 'inspect', container, '--format', '{{.Image}}')
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
                raise ValueError('Could not identify the current immutable image')
            source = None
            if COMPONENT == 'server':
                environment = json.loads(run('docker', 'inspect', container, '--format', '{{json .Config.Env}}'))
                source = next((item.split('=', 1)[1] for item in environment if item.startswith('CC_SOURCE_CODE_URL=')), None)
            run('docker', 'pull', report['image'])
            prior_report = state / 'deployed.json'
            if not pending.exists():
                atomic_json(previous, {'component': COMPONENT, 'project': config['project'], 'service': service,
                                      'image_id': image_id, 'source_url': source,
                                      'report': json.loads(prior_report.read_text()) if prior_report.exists() else None})
                atomic_json(pending, report)
            desired = override(service, report['image'], report['source_url'])
        atomic_json(current, desired)
        run(*base, '--file', str(current), 'up', '-d', '--no-deps', '--no-build', '--pull', 'never',
            '--wait', '--wait-timeout', '180', service)
        # Confirm the running bytes, then the public route through the existing proxy.
        container = run(*base, 'ps', '-q', service)
        expected_id = run('docker', 'image', 'inspect', desired['services'][service]['image'], '--format', '{{.Id}}')
        if run('docker', 'inspect', container, '--format', '{{.Image}}') != expected_id:
            raise RuntimeError('Running container differs from the selected immutable image')
        for attempt in range(30):
            try:
                probe(config, report)
                break
            except (OSError, RuntimeError, ValueError, KeyError):
                if attempt == 29:
                    raise RuntimeError('Release is running but public verification failed; rollback snapshot retained') from None
                time.sleep(2)
        if report:
            atomic_json(state / 'deployed.json', report)
        elif rollback:
            (state / 'deployed.json').unlink(missing_ok=True)
        pending.unlink(missing_ok=True)
        print(f'{COMPONENT} verified; previous image retained for explicit rollback.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--tag')
    parser.add_argument('--revision')
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    if args.rollback:
        if args.manifest or args.tag or args.revision:
            parser.error('--rollback uses only the retained previous deployment')
        report = None
    else:
        if not args.manifest or not args.tag or not args.revision:
            parser.error('Deploy requires --manifest, --tag and --revision from the tagged workflow')
        report = validate_manifest(json.loads(args.manifest.read_text()), args.tag, args.revision)
    deploy(json.loads(args.config.read_text()), report, args.rollback)


if __name__ == '__main__':
    main()
