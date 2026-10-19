#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Create a new release as a draft, attach receipts, then publish once without replacing assets."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from release import IMAGE, REPOSITORY, release_plan

COMPONENT = 'server'


def main():
    plan = release_plan()
    manifest_path = Path(f'dist/{COMPONENT}-image.json')
    report = json.loads(manifest_path.read_text())
    for key in ('version', 'revision', 'tag', 'source_url'):
        if report.get(key) != plan[key]:
            raise ValueError('Build manifest does not match the validated release source')
    if report.get('release') is not True or not re.fullmatch(re.escape(IMAGE) + r'@sha256:[0-9a-f]{64}', report.get('image', '')):
        raise ValueError('Release requires the verified immutable image manifest')
    if report.get('digest') != report['image'].split('@')[1]:
        raise ValueError('Image digest fields disagree')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '')
    if not run_id.isdigit() or not attempt.isdigit():
        raise ValueError('A GitHub Actions build run and attempt are required')
    receipt = dict(report, workflow_run_url=f'https://github.com/{REPOSITORY}/actions/runs/{run_id}',
                   workflow_run_attempt=int(attempt),
                   manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest())
    receipt_path = Path('dist/build-receipt.json')
    receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
    checksum_path = Path('dist/SHA256SUMS')
    assets = [manifest_path, receipt_path]
    checksum_path.write_text(''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n' for path in assets))
    assets.append(checksum_path)
    notes = Path('dist/release-notes.md')
    notes_root = Path('server/docs/releases' if COMPONENT == 'server' else 'releases')
    authored_notes = notes_root / f'{plan["version"]}.md'
    description = authored_notes.read_text() if authored_notes.exists() else f'ConsoleCrypt {COMPONENT} {plan["version"]}\n'
    notes.write_text(description.rstrip() + '\n\n'
                     f'Image: `{report["image"]}`\n\n'
                     f'[Source]({plan["source_url"]}) · [Verified build]({receipt["workflow_run_url"]})\n\n'
                     'Linux AMD64 + ARM64. Deploy the digest in the attached image manifest.\n')
    # create fails if this tag already has any release. Never use --clobber or edit
    # an existing published release. Draft staging also supports GitHub immutable releases.
    subprocess.run(['gh', 'release', 'create', plan['tag'], *map(str, assets), '--repo', REPOSITORY,
                    '--verify-tag', '--target', plan['revision'], '--draft',
                    '--title', f'ConsoleCrypt {COMPONENT} {plan["version"]}', '--notes-file', str(notes)], check=True)
    uploaded = json.loads(subprocess.check_output(['gh', 'release', 'view', plan['tag'], '--repo', REPOSITORY,
                                                 '--json', 'isDraft,assets,targetCommitish'], text=True))
    expected = {path.name: path.stat().st_size for path in assets}
    actual = {asset['name']: asset['size'] for asset in uploaded['assets']}
    if uploaded['isDraft'] is not True or uploaded['targetCommitish'] != plan['revision'] or actual != expected:
        raise ValueError('Draft release assets/source differ from the build; leave draft for inspection')
    subprocess.run(['gh', 'release', 'edit', plan['tag'], '--repo', REPOSITORY, '--draft=false', '--latest'], check=True)


if __name__ == '__main__':
    main()
