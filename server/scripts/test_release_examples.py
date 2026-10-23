# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
"""example_versions.py: examples follow server/Cargo.toml (runs with test_release*.py in CI)."""

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("example_versions", HERE / "example_versions.py")
ev = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ev)


class ExampleVersionsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        for name, _, _ in ev.TARGETS + [("server/Cargo.toml", None, None)]:
            target = self.tmp / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ev.ROOT / name, target)

    def set_cargo(self, version):
        path = self.tmp / "server/Cargo.toml"
        text = path.read_text()
        current = ev.cargo_version(self.tmp)
        path.write_text(text.replace(f'version = "{current}"', f'version = "{version}"', 1))

    def test_repository_examples_match_cargo(self):
        expected, problems = ev.check()
        self.assertEqual(problems, [], f"run example_versions.py --write ({expected})")

    def test_older_examples_fail_and_write_fixes_them(self):
        self.set_cargo("99.1.0")
        _, problems = ev.check(self.tmp)
        self.assertEqual(len(problems), len(ev.TARGETS))
        self.assertTrue(all("older than server 99.1.0" in p for p in problems))
        _, changed = ev.write(self.tmp)
        self.assertEqual(len(changed), len(ev.TARGETS))
        self.assertEqual(ev.check(self.tmp)[1], [])
        compose = (self.tmp / "server/deploy/docker/compose.yaml").read_text()
        self.assertIn("consolecrypt-server:${CC_SERVER_VERSION:-99.1.0}", compose)

    def test_missing_pin_is_an_error(self):
        path = self.tmp / "server/helm/consolecrypt-server/Chart.yaml"
        path.write_text(path.read_text().replace("appVersion:", "appVersionX:"))
        with self.assertRaises(SystemExit):
            ev.check(self.tmp)


if __name__ == "__main__":
    unittest.main()
