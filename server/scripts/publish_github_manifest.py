#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
"""Publish a tag release manifest from the two tested architecture digests."""

import json
import os
from pathlib import Path
import re
import subprocess
from release import IMAGE, release_plan, require_absent


def main():
    plan = release_plan()
    image = IMAGE
    sha = plan['revision']
    version = plan['version']

    sources = []
    for architecture in ("amd64", "arm64"):
        digest = Path(f"dist/digests/{architecture}").read_text().strip()
        if not re.fullmatch(re.escape(image) + r"@sha256:[0-9a-f]{64}", digest):
            raise ValueError(f"Invalid {architecture} image digest")
        sources.append(digest)
    tags = [f"{image}:sha-{sha}", f"{image}:{version}"]
    for tag in tags:
        require_absent(tag)
    command = ["docker", "buildx", "imagetools", "create"]
    for tag in tags:
        command += ["--tag", tag]
    subprocess.run(command + sources, check=True)
    metadata = json.loads(subprocess.check_output([
        "docker", "buildx", "imagetools", "inspect", tags[0],
        "--format", "{{json .Manifest}}",
    ], text=True))
    digest = metadata["digest"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Registry returned an invalid manifest digest")
    report = {
        "version": version,
        "revision": sha,
        "source_url": plan["source_url"],
        "image": f"{image}@{digest}",
        "digest": digest,
        "tags": tags,
        "platforms": ["linux/amd64", "linux/arm64"],
        "release": True,
        "tag": plan["tag"],
    }
    Path("dist/server-image.json").write_text(json.dumps(report, indent=2) + "\n")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
        summary.write(f"Server {version}: `{image}@{digest}`\n\n")
        summary.write(f"[Matching source]({report['source_url']}) · amd64 + arm64\n")


if __name__ == "__main__":
    main()
