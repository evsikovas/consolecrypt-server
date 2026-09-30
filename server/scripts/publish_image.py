#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build, verify and publish the API-only server for amd64 and arm64.

CI uses its own short-lived registry credentials; local --verify-only needs none.
No production service/database is accessed. Test containers are always removed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
import tomllib
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = 'registry.evsikov.net/publics/consolecrypt/server'
PROJECT = 'https://git.evsikov.net/publics/consolecrypt'
PLATFORMS = ('linux/amd64', 'linux/arm64')


def run(*args, env=None, capture=True, **kwargs):
    return subprocess.run(args, check=True, env=env, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None, **kwargs)


def source_plan(root, env, allow_dirty=False):
    version = tomllib.loads((root / 'server/Cargo.toml').read_text())['package']['version']
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Server version must be a stable SemVer')
    revision = run('git', '-C', str(root), 'rev-parse', 'HEAD').stdout.strip()
    if env.get('CI_COMMIT_SHA', revision) != revision:
        raise ValueError('Checkout differs from CI_COMMIT_SHA')
    if not allow_dirty and run('git', '-C', str(root), 'status', '--porcelain', '--untracked-files=all').stdout:
        raise ValueError('Refusing to publish a dirty source checkout')
    if env.get('CC_IMAGE_REPOSITORY', REPOSITORY) != REPOSITORY:
        raise ValueError('Unexpected registry destination')
    if (root / 'server/web').exists() or (root / 'server/src/web.rs').exists():
        raise ValueError('Remove the embedded website before publishing the API image')
    lib = (root / 'server/src/lib.rs').read_text()
    if re.search(r'\bmod\s+web\b|\bweb\s*::\s*router', lib):
        raise ValueError('The API still includes the website router')
    tags = [f'sha-{revision}', f'{version}-{revision[:12]}']
    release = env.get('CI_COMMIT_TAG', '')
    if release:
        if release != f'server-v{version}':
            raise ValueError('Release tag must be server-v<server Cargo.toml version>')
        tags.append(version)
    return {'repository': REPOSITORY, 'revision': revision, 'version': version,
            'source': f'{PROJECT}/-/tree/{revision}', 'tags': tags,
            'platforms': list(PLATFORMS)}


def http(url, expected):
    try:
        response = urllib.request.urlopen(url, timeout=3)
    except urllib.error.HTTPError as err:
        response = err
    with response:
        if response.status != expected:
            raise RuntimeError(f'HTTP probe expected {expected}, got {response.status}')
        return response.headers.get('Content-Type', ''), response.read()


def wait_ready(probe, description, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            probe()
            return
        except (subprocess.CalledProcessError, OSError, RuntimeError):
            time.sleep(1)
    raise RuntimeError(f'{description} did not become ready within {timeout}s')


def verify_images(images, plan):
    suffix = secrets.token_hex(6)
    network = f'cc-image-check-{suffix}'
    postgres = f'{network}-db'
    server = f'{network}-api'
    test_env = os.environ.copy()
    test_env['POSTGRES_PASSWORD'] = secrets.token_urlsafe(32)
    test_env['CC_DATABASE_URL'] = f'postgres://postgres:{test_env["POSTGRES_PASSWORD"]}@{postgres}:5432/postgres'
    created = []
    run('docker', 'network', 'create', network)
    try:
        run('docker', 'run', '-d', '--name', postgres, '--network', network,
            '-e', 'POSTGRES_PASSWORD', 'postgres:16-alpine', env=test_env)
        created.append(postgres)
        wait_ready(lambda: run('docker', 'exec', postgres, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'), 'Test PostgreSQL')
        for platform, image in images:
            run('docker', 'run', '-d', '--name', server, '--platform', platform,
                '--network', network, '-p', '127.0.0.1::8080', '-e', 'CC_DATABASE_URL',
                '-e', 'CC_MAIL_TRANSPORT=disabled', image, env=test_env)
            created.append(server)
            port = json.loads(run('docker', 'inspect', server).stdout)[0]['NetworkSettings']['Ports']['8080/tcp'][0]['HostPort']
            base = f'http://127.0.0.1:{port}'
            wait_ready(lambda: http(base + '/readyz', 200), f'{platform} server')
            http(base + '/healthz', 200)
            _, data = http(base + '/v1/meta', 200)
            meta = json.loads(data)
            if meta['server_version'] != plan['version'] or meta['source_code_url'] != plan['source']:
                raise RuntimeError('Image version/source does not match the checkout')
            for path in ('/', '/account', '/privacy', '/assets/api.js', '/assets/site.css', '/v1/unknown'):
                content_type, body = http(base + path, 404)
                if not content_type.startswith('application/json') or json.loads(body)['code'] != 'not_found':
                    raise RuntimeError('API image served non-API content')
            http(base + '/v1/auth/me', 401)
            run('docker', 'exec', server, '/usr/local/bin/consolecrypt-server', 'healthcheck')
            run('docker', 'rm', '-f', server)
            created.remove(server)
            print(f'Passed {platform}: readiness, version/source, API auth, no website.', flush=True)
    finally:
        for container in reversed(created):
            subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def publish(images, plan, env):
    # Preserve the selected daemon when using a private temporary Docker config.
    endpoint = run('docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}').stdout.strip()
    plugins = json.loads(run('docker', 'info', '--format', '{{json .ClientInfo.Plugins}}').stdout)
    plugin_dirs = sorted({str(Path(p['Path']).parent) for p in plugins})
    with tempfile.TemporaryDirectory(prefix='cc-registry-') as auth_dir:
        Path(auth_dir, 'config.json').write_text(json.dumps({'cliPluginsExtraDirs': plugin_dirs}))
        docker_env = dict(env, DOCKER_CONFIG=auth_dir)
        docker_env.setdefault('DOCKER_HOST', endpoint)
        docker_env.pop('DOCKER_CONTEXT', None)
        run('docker', 'login', 'registry.evsikov.net', '--username', env['CI_REGISTRY_USER'],
            '--password-stdin', input=env['CI_REGISTRY_PASSWORD'] + '\n', env=docker_env)
        # Never overwrite an existing release or commit tag.
        for tag in plan['tags']:
            result = subprocess.run(['docker', 'buildx', 'imagetools', 'inspect', f'{REPOSITORY}:{tag}', '--raw'],
                                    env=docker_env, text=True, capture_output=True)
            if result.returncode == 0:
                raise RuntimeError(f'Tag {tag} already exists; use the published image or a new commit')
            if not re.search(r'not found|manifest unknown', result.stderr, re.I):
                raise RuntimeError('Cannot confirm that registry tag is absent; refusing publication')
        sources = []
        for platform, image in images:
            arch = platform.split('/')[1]
            reference = f'{REPOSITORY}:sha-{plan["revision"]}-{arch}'
            run('docker', 'tag', image, reference)
            run('docker', 'push', reference, env=docker_env, capture=False)
            sources.append(reference)
        for tag in plan['tags']:
            run('docker', 'buildx', 'imagetools', 'create', '-t', f'{REPOSITORY}:{tag}', *sources,
                env=docker_env, capture=False)
            manifest = json.loads(run('docker', 'buildx', 'imagetools', 'inspect', f'{REPOSITORY}:{tag}', '--raw', env=docker_env).stdout)
            actual = {f'{m["platform"]["os"]}/{m["platform"]["architecture"]}' for m in manifest['manifests']}
            if not set(PLATFORMS).issubset(actual):
                raise RuntimeError('Published index is missing a required platform')
        raw = run('docker', 'buildx', 'imagetools', 'inspect', sources[0].rsplit(':', 1)[0] + ':' + plan['tags'][0], env=docker_env).stdout
        digest = re.search(r'^Digest:\s+(sha256:[a-f0-9]{64})$', raw, re.M)
        if not digest:
            raise RuntimeError('Cannot read the published image digest')
        plan['digest'] = digest.group(1)
        # Verify registry pull access, not just the local build tags.
        for platform in PLATFORMS:
            run('docker', 'pull', '--platform', platform, f'{REPOSITORY}@{plan["digest"]}', env=docker_env, capture=False)
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-only', action='store_true', help='Build/test without registry credentials or publication')
    parser.add_argument('--allow-dirty', action='store_true', help='Only with --verify-only, for local development')
    args = parser.parse_args()
    if args.allow_dirty and not args.verify_only:
        parser.error('--allow-dirty requires --verify-only')
    env = os.environ.copy()
    plan = source_plan(ROOT, env, allow_dirty=args.allow_dirty)
    if not args.verify_only:
        if env.get('CI_PROJECT_PATH') != 'publics/consolecrypt' or not env.get('CI_REGISTRY_USER') or not env.get('CI_REGISTRY_PASSWORD'):
            raise ValueError('Publish from the ConsoleCrypt GitLab job using its registry credentials')
    images = []
    for platform in PLATFORMS:
        image = f'consolecrypt-server:verify-{plan["revision"][:12]}-{platform.split("/")[1]}'
        run('docker', 'buildx', 'build', '--platform', platform, '--load',
            '--build-arg', f'SOURCE_REVISION={plan["revision"]}',
            '--build-arg', f'SERVER_VERSION={plan["version"]}',
            '--build-arg', f'SOURCE_URL={plan["source"]}',
            '-f', str(ROOT / 'server/Dockerfile'), '-t', image, str(ROOT), capture=False)
        images.append((platform, image))
    verify_images(images, plan)
    if args.verify_only:
        print('Both platform images verified; nothing published.', flush=True)
    else:
        result = publish(images, plan, env)
        output = ROOT / 'dist/server-image.json'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + '\n')
        print(f'Published {REPOSITORY}@{result["digest"]}', flush=True)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        # Captured Docker/DB stderr can contain credentials. Do not echo it.
        raise SystemExit(f'Command failed (exit {error.returncode}); no credentials or container logs printed.') from None
    except (ValueError, RuntimeError) as error:
        raise SystemExit(str(error)) from None
