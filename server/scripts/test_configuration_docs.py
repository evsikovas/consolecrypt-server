# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
"""docs/public/CONFIGURATION.md lists exactly the settings the server accepts.

The accepted keys come from the code, not from a hand-written list:
* server/src/config/keys.rs — every key the configuration loader reads from the
  environment or the JSON file (a Rust test keeps it in step with config.rs,
  config/auth.rs and the CC_LIMIT_* catalogue);
* the environment-only variables read outside the loader (CC_CONFIG_FILE,
  the CC_LOG/RUST_LOG log filter, the OTEL_* trace endpoints);
* the Helm chart's _helpers.tpl, whose CC_* → values mapping must match the
  Helm column of the reference.
"""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "server"
DOC = ROOT / "docs/public/CONFIGURATION.md"
KEYS_RS = SERVER / "src/config/keys.rs"
CONFIG_SOURCES = [SERVER / "src/config.rs", SERVER / "src/config/auth.rs"]
FILE_RS = SERVER / "src/config/file.rs"
TELEMETRY_RS = SERVER / "src/telemetry.rs"
HELPERS = SERVER / "helm/consolecrypt-server/templates/_helpers.tpl"

# Variables of the Docker Compose examples: read by Compose, not by the server.
DEPLOYMENT_ONLY = {
    "CC_SERVER_VERSION", "CC_SERVER_IMAGE", "CC_DOMAIN", "CC_HTTP_PORT",
    "CC_POSTGRES_ADMIN_PASSWORD", "CC_POSTGRES_PASSWORD", "CC_METRICS_PORT",
}
# Named on purpose: a placeholder and the *_FILE variants that do NOT exist.
ILLUSTRATIVE = {"CC_X", "CC_DATABASE_PASSWORD_FILE", "CC_SMTP_PASSWORD_FILE"}
# A whole token: a key directly followed by "_*" or "_<NAME>" is a pattern.
TOKEN = re.compile(r"\b(?:CC|OTEL|RUST)_[A-Z0-9_]*[A-Z0-9](?![A-Za-z0-9_<*])")


def accepted_keys():
    keys = re.findall(r'^\s*"(CC_[A-Z0-9_]+)",\s*$', KEYS_RS.read_text(), re.M)
    if len(keys) < 100 or len(keys) != len(set(keys)):
        raise AssertionError("cannot parse the key list in server/src/config/keys.rs")
    return set(keys)


def environment_only_keys():
    keys = set()
    file_rs = FILE_RS.read_text()
    keys.update(re.findall(r'key == "(CC_[A-Z0-9_]+)"', file_rs))
    telemetry = TELEMETRY_RS.read_text()
    keys.update(re.findall(r'try_from_env\("([A-Z0-9_]+)"\)', telemetry))
    keys.update(re.findall(r'"(OTEL_[A-Z0-9_]+)"', telemetry))
    if "try_from_default_env" in telemetry:
        keys.add("RUST_LOG")  # tracing-subscriber's default variable
    if not {"CC_CONFIG_FILE", "CC_LOG", "RUST_LOG"} <= keys:
        raise AssertionError(f"cannot find the environment-only variables: {sorted(keys)}")
    return keys


def read_keys():
    """Keys the loader reads directly with get("…")."""
    keys = set()
    for source in CONFIG_SOURCES:
        keys.update(re.findall(r'get\("((?:CC_|DATABASE_)[A-Z0-9_]*)"\)', source.read_text()))
    return keys


def helm_mapping():
    """CC_* → Helm values path for the simple references in _helpers.tpl."""
    scopes = {
        "$c": "config", "$dp": "config.deviceProtection", "$sharing": "config",
        "$a": "auth", "$o": "auth.oidc", "$l": "auth.ldap",
        ".Values": "", "$.Values": "",
    }
    mapping = {}
    pattern = re.compile(r'"(CC_[A-Z0-9_]+)"\s+(\$\.Values|\.Values|\$[a-z]+)\.([A-Za-z0-9.]+)')
    for key, scope, path in pattern.findall(HELPERS.read_text()):
        if scope not in scopes:
            continue
        prefix = scopes[scope]
        mapping[key] = f"{prefix}.{path}" if prefix else path
    if len(mapping) < 60:
        raise AssertionError("cannot parse the CC_* mapping in _helpers.tpl")
    return mapping


def sections():
    text = DOC.read_text()
    russian, separator, english = text.partition("\n## English\n")
    if not separator:
        raise AssertionError("CONFIGURATION.md needs a '## English' section")
    return russian, english


class ConfigurationDocsTest(unittest.TestCase):
    def test_loader_reads_only_accepted_keys(self):
        # DATABASE_URL is the legacy alias the loader still asks for.
        unknown = read_keys() - accepted_keys() - environment_only_keys() - {"DATABASE_URL"}
        self.assertEqual(unknown, set(), "keys read by config.rs/auth.rs but not in keys.rs")

    def test_every_accepted_key_is_documented_in_both_languages(self):
        expected = accepted_keys() | environment_only_keys()
        for name, text in zip(("Russian", "English"), sections()):
            missing = sorted(key for key in expected if f"`{key}`" not in text)
            self.assertEqual(missing, [], f"{name} part of CONFIGURATION.md lacks these keys")

    def test_every_documented_key_exists(self):
        known = accepted_keys() | environment_only_keys() | DEPLOYMENT_ONLY | ILLUSTRATIVE
        self.assertEqual(ILLUSTRATIVE & accepted_keys(), set(), "an illustrative key became real")
        documented = set(TOKEN.findall(DOC.read_text()))
        self.assertEqual(sorted(documented - known), [],
                         "CONFIGURATION.md mentions keys the server does not accept")

    def test_every_limit_name_is_documented(self):
        names = set()
        for key in accepted_keys():
            match = re.fullmatch(r"CC_LIMIT_([A-Z_]+?)_(RATE|BURST|PER_HOUR|PER_DAY)", key)
            if match:
                names.add(match.group(1).lower())
        self.assertGreaterEqual(len(names), 18)
        for name, text in zip(("Russian", "English"), sections()):
            missing = sorted(n for n in names if f"| `{n}`" not in text)
            self.assertEqual(missing, [], f"{name} limit table lacks these limits")

    def test_helm_paths_match_the_chart(self):
        rows = {}
        for line in DOC.read_text().splitlines():
            match = re.match(r"\| `((?:CC|OTEL|RUST)_[A-Z0-9_]+)` \| ([^|]*) \|", line)
            if match:
                rows.setdefault(match.group(1), []).append(match.group(2))
        problems = []
        for key, path in sorted(helm_mapping().items()):
            cells = rows.get(key, [])
            if len(cells) != 2:
                problems.append(f"{key}: expected one table row per language, found {len(cells)}")
            elif any(f"`{path}`" not in cell for cell in cells):
                problems.append(f"{key}: Helm column should name `{path}`")
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
