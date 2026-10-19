#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Validate the immutable source of a tag release before building or deploying."""
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

REPOSITORY = 'evsikovas/consolecrypt-server'
IMAGE = f'ghcr.io/{REPOSITORY}'
SEMVER = r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


def release_plan(env=None):
    env = os.environ if env is None else env
    if env.get('GITHUB_REPOSITORY') != REPOSITORY:
        raise ValueError('Release only from the upstream repository')
    if env.get('GITHUB_EVENT_NAME') != 'push':
        raise ValueError('Release only from a tag push')
    version = tomllib.loads(Path('server/Cargo.toml').read_text())['package']['version']
    if not re.fullmatch(SEMVER, version):
        raise ValueError('Expected a stable server version')
    tag = f'v{version}'
    if env.get('GITHUB_REF') != f'refs/tags/{tag}':
        raise ValueError('Release tag must be v<server/Cargo.toml version>')
    sha = env.get('GITHUB_SHA', '')
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('Expected a full source commit ID')
    if git('rev-parse', 'HEAD') != sha or git('rev-parse', f'refs/tags/{tag}^{{commit}}') != sha:
        raise ValueError('Checkout, tag and release commit must match')
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Release source checkout must be clean')
    # checkout fetch-depth: 0 supplies origin/main and annotated tag objects.
    subprocess.run(['git', 'merge-base', '--is-ancestor', sha, 'refs/remotes/origin/main'], check=True)
    return {'version': version, 'revision': sha, 'tag': tag,
            'source_url': f'https://github.com/{REPOSITORY}/tree/{sha}',
            'repository': IMAGE}


def require_absent(reference):
    """Fail closed on authentication/network failures; never replace release tags."""
    result = subprocess.run(['docker', 'buildx', 'imagetools', 'inspect', reference, '--raw'],
                            text=True, capture_output=True)
    if result.returncode == 0:
        raise ValueError(f'Image reference already exists: {reference}')
    absent = ('manifest unknown' in result.stderr.lower() or
              re.search(re.escape(reference) + r': not found(?:\s|$)', result.stderr, re.IGNORECASE))
    if not absent:
        raise RuntimeError('Cannot confirm absence of the release image')


def main():
    plan = release_plan()
    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a') as stream:
            for key, value in plan.items():
                stream.write(f'{key}={value}\n')
    print(json.dumps(plan, indent=2))


if __name__ == '__main__':
    main()
