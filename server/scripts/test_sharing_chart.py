#!/usr/bin/env python3
"""Offline Helm tests: sharing stays off unless explicitly enabled safely."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

CHART = Path(__file__).resolve().parents[1] / "helm/consolecrypt-server"
FLAGS = {
    "objectSharingEnabled": "CC_OBJECT_SHARING_ENABLED",
    "sharedGroupsEnabled": "CC_SHARED_GROUPS_ENABLED",
    "sharedSecretsEnabled": "CC_SHARED_SECRETS_ENABLED",
    "sharedKubeContextsEnabled": "CC_SHARED_KUBE_CONTEXTS_ENABLED",
    "sharedDbConnectionsEnabled": "CC_SHARED_DB_CONNECTIONS_ENABLED",
    "sharingOwnerOnlineEnrollmentEnabled": "CC_SHARING_OWNER_ONLINE_ENROLLMENT_ENABLED",
}


def render(config):
    with tempfile.TemporaryDirectory(prefix="cc-chart-test-") as directory:
        values = Path(directory) / "values.json"
        values.write_text(json.dumps({"database": {"existingSecret": "test-db"}, "config": config}))
        return subprocess.run(["helm", "template", "test", str(CHART), "-f", str(values)],
                              capture_output=True, text=True, check=False)


class SharingChartTests(unittest.TestCase):
    def rendered_flags(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        return {env: re.search(r'^  ' + env + r': "(true|false)"$', result.stdout, re.M).group(1)
                for env in FLAGS.values()}

    def test_default_flags_are_explicit_false(self):
        result = render({})
        self.assertEqual(set(self.rendered_flags(result).values()), {"false"})
        self.assertNotIn("kind: Job", result.stdout)

    def test_extensions_are_independent(self):
        for extension in list(FLAGS)[1:]:
            with self.subTest(extension=extension):
                values = self.rendered_flags(render({"objectSharingEnabled": True, extension: True}))
                for key, env in FLAGS.items():
                    self.assertEqual(values[env], str(key in ["objectSharingEnabled", extension]).lower())

    def test_extensions_require_general_sharing(self):
        for extension in list(FLAGS)[1:]:
            with self.subTest(extension=extension):
                result = render({extension: True})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("extensions require", result.stderr)

    def test_sharing_requires_strict_proofs(self):
        for proofs in [False, "false", "true"]:
            with self.subTest(proofs=proofs):
                result = render({"objectSharingEnabled": True, "requireRequestProof": proofs})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("requireRequestProof=true", result.stderr)

    def test_removed_legacy_keys_fail_closed(self):
        # Helm coalesces explicit null by removing the key. Old --reuse-values
        # releases can also lack it; both must render an explicit false.
        result = render({flag: None for flag in FLAGS})
        self.assertEqual(set(self.rendered_flags(result).values()), {"false"})

    def test_flags_reject_non_booleans(self):
        for flag in FLAGS:
            for invalid in ["false", "true", 0, 1]:
                with self.subTest(flag=flag, invalid=invalid):
                    result = render({flag: invalid})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("must be a boolean", result.stderr)


class DeviceProtectionChartTests(unittest.TestCase):
    def env(self, result, name):
        self.assertEqual(result.returncode, 0, result.stderr)
        match = re.search(r'^  ' + name + r': "([^"]*)"$', result.stdout, re.M)
        return match and match.group(1)

    def test_off_by_default_and_with_reused_old_values(self):
        for config in [{}, {"deviceProtection": None}, {"deviceProtection": {"enabled": None}}]:
            with self.subTest(config=config):
                self.assertEqual(self.env(render(config), "CC_DEVICE_PROTECTION_ENABLED"), "false")

    def test_enabled_with_limits(self):
        result = render({"deviceProtection": {"enabled": True, "quarantineDays": 7,
                                              "envelopesPerAccountPerHour": 2}})
        self.assertEqual(self.env(result, "CC_DEVICE_PROTECTION_ENABLED"), "true")
        self.assertEqual(self.env(result, "CC_DEVICE_QUARANTINE_DAYS"), "7")
        self.assertEqual(self.env(result, "CC_ENVELOPE_LIMIT_ACCOUNT_PER_HOUR"), "2")

    def test_rejects_non_boolean(self):
        result = render({"deviceProtection": {"enabled": "true"}})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be a boolean", result.stderr)


if __name__ == "__main__":
    unittest.main()
