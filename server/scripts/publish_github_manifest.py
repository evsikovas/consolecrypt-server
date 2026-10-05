#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
"""Combine the two tested GitHub Actions images; never deploy production."""

import json
import os
from pathlib import Path
import re
import subprocess
import tomllib


def main():
    repository = "evsikovas/consolecrypt-server"
    if os.environ.get("GITHUB_REPOSITORY") != repository:
        raise ValueError("Publishing is restricted to the upstream repository")
    image = f"ghcr.io/{repository}"
    sha = os.environ["GITHUB_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Expected a full commit ID")
    version = tomllib.loads(Path("server/Cargo.toml").read_text())["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Expected a stable server version")
    ref = os.environ["GITHUB_REF"]
    release = ref == f"refs/tags/server-v{version}"
    if ref != "refs/heads/main" and not release:
        raise ValueError("Publish only main or the matching server release tag")

    sources = []
    for architecture in ("amd64", "arm64"):
        digest = Path(f"dist/digests/{architecture}").read_text().strip()
        if not re.fullmatch(re.escape(image) + r"@sha256:[0-9a-f]{64}", digest):
            raise ValueError(f"Invalid {architecture} image digest")
        sources.append(digest)
    tags = [f"{image}:sha-{sha}", f"{image}:{version}-{sha[:12]}"]
    # Main builds are candidates. Only an explicit server-vX.Y.Z tag moves the
    # stable aliases, so an unrelated README edit cannot replace a release.
    if release:
        tags += [f"{image}:{version}", f"{image}:latest"]
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
        "source_url": f"https://github.com/{repository}/tree/{sha}",
        "image": f"{image}@{digest}",
        "digest": digest,
        "tags": tags,
        "platforms": ["linux/amd64", "linux/arm64"],
        "release": release,
    }
    Path("dist/server-image.json").write_text(json.dumps(report, indent=2) + "\n")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
        summary.write(f"Server {version}: `{image}@{digest}`\n\n")
        summary.write(f"[Matching source]({report['source_url']}) · amd64 + arm64\n")


if __name__ == "__main__":
    main()
