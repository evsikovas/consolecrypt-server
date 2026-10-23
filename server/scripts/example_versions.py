#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
"""Keep the self-hosting examples on the server version of server/Cargo.toml.

The Docker Compose example (`CC_SERVER_VERSION` default), its init-config.py
and reference .env, the Helm chart `appVersion` and HOSTING.md all name one
server release; the published image tag `ghcr.io/evsikovas/consolecrypt-server:X.Y.Z`
follows from it.

    python3 server/scripts/example_versions.py --write   # in the version-bump commit
    python3 server/scripts/example_versions.py --check   # CI: fails on any mismatch

`--check` runs in the tag workflow before anything is built, so a release whose
examples still point at an older (or a not yet existing) server is refused.
"""

import argparse
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
VERSION = r"(?P<v>\d+\.\d+\.\d+)"
# (file, pattern with a `v` group, minimum number of occurrences)
TARGETS = [
    ("server/deploy/docker/compose.yaml", r"\$\{CC_SERVER_VERSION:-" + VERSION + r"\}", 1),
    ("server/deploy/docker/init-config.py", r'(?m)^VERSION = "' + VERSION + '"$', 1),
    ("server/deploy/docker/.env.example", r"(?m)^CC_SERVER_VERSION=" + VERSION + "$", 1),
    ("server/helm/consolecrypt-server/Chart.yaml", r'(?m)^appVersion: "' + VERSION + '"$', 1),
    ("docs/public/HOSTING.md", r"CC_SERVER_VERSION=" + VERSION, 1),
]


def cargo_version(root=ROOT):
    text = (root / "server/Cargo.toml").read_text(encoding="utf-8")
    package = text.split("[package]", 1)[1].split("\n[", 1)[0]
    match = re.search(r'(?m)^version = "(\d+\.\d+\.\d+)"$', package)
    if not match:
        raise SystemExit("server/Cargo.toml: no [package] version")
    return match.group(1)


def key(version):
    return tuple(int(part) for part in version.split("."))


def scan(root=ROOT):
    """[(file, found versions)] for every target."""
    found = []
    for name, pattern, minimum in TARGETS:
        text = (root / name).read_text(encoding="utf-8")
        versions = [m.group("v") for m in re.finditer(pattern, text)]
        if len(versions) < minimum:
            raise SystemExit(f"{name}: expected a pinned server version ({pattern})")
        found.append((name, versions))
    return found


def check(root=ROOT):
    expected = cargo_version(root)
    problems = []
    for name, versions in scan(root):
        for version in sorted(set(versions), key=key):
            if version != expected:
                relation = "older than" if key(version) < key(expected) else "newer than"
                problems.append(f"{name}: {version} is {relation} server {expected}")
    return expected, problems


def write(root=ROOT):
    expected = cargo_version(root)
    changed = []
    for name, pattern, _ in TARGETS:
        path = root / name
        text = path.read_text(encoding="utf-8")

        def repl(match):
            start, end = match.span("v")
            whole = match.group(0)
            offset = match.start()
            return whole[: start - offset] + expected + whole[end - offset :]

        updated = re.sub(pattern, repl, text)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            changed.append(name)
    return expected, changed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    if args.write:
        expected, changed = write()
        print(f"examples pinned to server {expected}: " + (", ".join(changed) or "already current"))
        return 0
    expected, problems = check()
    if problems:
        print("Self-hosting examples do not match the server version; run "
              "`python3 server/scripts/example_versions.py --write`:", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1
    print(f"examples pinned to server {expected}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
