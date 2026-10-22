#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
"""Offline Helm tests: enterprise sign-in (`auth:` block, server 0.2.0)."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

CHART = Path(__file__).resolve().parents[1] / "helm/consolecrypt-server"


def render(values):
    base = {"database": {"existingSecret": "test-db"}}
    base.update(values)
    with tempfile.TemporaryDirectory(prefix="cc-chart-test-") as directory:
        path = Path(directory) / "values.json"
        path.write_text(json.dumps(base))
        return subprocess.run(["helm", "template", "test", str(CHART), "-f", str(path)],
                              capture_output=True, text=True, check=False)


OIDC = {
    "config": {"publicUrl": "https://sync.acme.test"},
    "auth": {"mode": "enterprise", "provider": "oidc", "allowedDomains": ["acme.test"],
             "oidc": {"preset": "keycloak", "issuer": "https://kc.acme.test/realms/acme",
                      "clientId": "consolecrypt", "existingSecret": "consolecrypt-oidc"}},
}
LDAP = {
    "auth": {"mode": "enterprise", "provider": "ldap",
             "ldap": {"url": "ldaps://dc1.acme.local:636", "bindDn": "CN=svc,DC=acme,DC=local",
                      "baseDn": "DC=acme,DC=local", "existingSecret": "consolecrypt-ldap",
                      "caKey": "ca.pem", "requiredGroup": "CN=CC,DC=acme,DC=local"}},
}


def merged(base, **auth):
    values = json.loads(json.dumps(base))
    for key, value in auth.items():
        section, _, field = key.partition("__")
        if field:
            values["auth"][section][field] = value
        else:
            values["auth"][section] = value
    return values


class AuthChartTests(unittest.TestCase):
    def ok(self, values):
        result = render(values)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def fails(self, values, text):
        result = render(values)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(text, result.stderr)

    def test_standard_by_default(self):
        out = self.ok({})
        self.assertNotIn("CC_AUTH_MODE", out)
        self.assertNotIn("consolecrypt-auth", out)

    def test_oidc_renders_files_and_mount(self):
        out = self.ok(OIDC)
        for line in ("CC_AUTH_MODE: enterprise", "CC_AUTH_PROVIDER: oidc",
                     "CC_OIDC_ISSUER: https://kc.acme.test/realms/acme",
                     "CC_OIDC_CLIENT_SECRET_FILE: /run/secrets/consolecrypt-auth/client-secret",
                     "CC_OIDC_TOKEN_KEY_FILE: /run/secrets/consolecrypt-auth/token-key",
                     "CC_AUTH_ALLOWED_DOMAINS: acme.test",
                     "secretName: consolecrypt-oidc",
                     "mountPath: /run/secrets/consolecrypt-auth"):
            self.assertIn(line, out)
        # Secret values never land in the ConfigMap.
        self.assertNotIn("CLIENT_SECRET:", out)

    def test_oidc_requires_issuer_secret_and_public_url(self):
        self.fails(merged(OIDC, oidc__issuer=""), "auth.oidc.issuer")
        self.fails(merged(OIDC, oidc__existingSecret=""), "existingSecret")
        values = merged(OIDC)
        values["config"] = {"publicUrl": ""}
        self.fails(values, "config.publicUrl")

    def test_ldap_renders_and_refuses_plain_ldap(self):
        out = self.ok(LDAP)
        for line in ("CC_LDAP_URL: ldaps://dc1.acme.local:636",
                     "CC_LDAP_BIND_PASSWORD_FILE: /run/secrets/consolecrypt-auth/bind-password",
                     "CC_LDAP_CA_FILE: /run/secrets/consolecrypt-auth/ca.pem",
                     'CC_LDAP_MAX_FAILURES: "3"',
                     "secretName: consolecrypt-ldap"):
            self.assertIn(line, out)
        self.fails(merged(LDAP, ldap__url="ldap://dc1.acme.local:389"), "plain ldap://")
        self.ok(merged(LDAP, ldap__url="ldap://dc1.acme.local:389", ldap__starttls=True))
        self.fails(merged(LDAP, ldap__bindDn=""), "auth.provider=ldap requires")

    def test_rejects_bad_mode_and_provider(self):
        self.fails({"auth": {"mode": "sso"}}, "auth.mode")
        self.fails({"auth": {"mode": "enterprise", "provider": "saml"}}, "auth.provider")


if __name__ == "__main__":
    unittest.main()
