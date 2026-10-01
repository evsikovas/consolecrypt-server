#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
"""Exercise this Compose example in disposable, uniquely named local containers.

Requires Docker Compose >= 2.24.4 (or 5.x), Python 3.9+, and the example images.
Publishes only random loopback ports. Never reads production configuration.
Removes only its own Compose project, test volumes and private temporary files.
No secrets, full environment, SQL dump or container logs are printed.
"""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def main():
    directory = Path(__file__).resolve().parent
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("Docker CLI is required")
    spec = importlib.util.spec_from_file_location("init_config", directory / "init-config.py")
    config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config)
    project = "cc-compose-test-" + uuid.uuid4().hex[:12]
    env = {key: value for key, value in os.environ.items() if not key.startswith("CC_")}
    checks = []

    with tempfile.TemporaryDirectory(prefix=project + "-") as temporary:
        private = Path(temporary)
        private.chmod(0o700)
        special_password = uuid.uuid4().hex + "'$#${CC_DOMAIN} $$\\\" \\ tail\\"
        configuration = config.create(private / "private", "localhost", {
            "CC_MAIL_TRANSPORT": "disabled",
            "CC_MAIL_FROM": "ConsoleCrypt <test@example.invalid>",
            "CC_SMTP_PASSWORD": special_password,
        })
        assert configuration.stat().st_mode & 0o777 == 0o600
        original = configuration.read_bytes()
        try:
            config.create(private / "private", "localhost", {})
        except FileExistsError:
            pass
        else:
            raise AssertionError("Existing configuration was overwritten")
        assert configuration.read_bytes() == original
        checks.append("private environment 0600; existing credentials preserved")
        # Real routing file; only certificate issuance changes to a local CA.
        caddyfile = private / "Caddyfile"
        caddyfile.write_text((directory / "Caddyfile").read_text().replace(
            "{$CC_DOMAIN} {", "{$CC_DOMAIN} {\n\ttls internal", 1))
        override = private / "override.yaml"
        # JSON is valid YAML; !override replaces production ports instead of merging.
        override.write_text(
            "services:\n  server:\n    ports: !override\n"
            '      - "127.0.0.1:0:8080"\n'
            "  caddy:\n    ports: !override\n"
            '      - "127.0.0.1:0:443"\n'
            "    volumes:\n      - type: bind\n"
            "        source: " + json.dumps(str(caddyfile)) + "\n"
            "        target: /etc/caddy/Caddyfile\n        read_only: true\n"
        )
        compose = [docker, "compose", "--project-name", project,
                   "--env-file", str(configuration), "-f", str(directory / "compose.yaml"),
                   "-f", str(override), "--profile", "https"]

        def run(args, data=None):
            result = subprocess.run(args, input=data, capture_output=True, env=env)
            if result.returncode:
                raise RuntimeError("Command failed (output suppressed to protect configuration): "
                                   + " ".join(args[:2]))
            return result.stdout

        def cc(*args, data=None):
            return run(compose + list(args), data)

        def sql(statement, db="consolecrypt"):
            return cc("exec", "-T", "postgres", "psql", "-X", "-qAt",
                      "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", db,
                      data=statement.encode()).decode().strip()

        def inspect_service(service):
            identifier = cc("ps", "-q", service).decode().strip()
            return json.loads(run([docker, "inspect", identifier]))[0]

        def endpoint(service, port):
            # Inspect only this test container. Never print its environment.
            info = inspect_service(service)
            mapping = info["NetworkSettings"]["Ports"][f"{port}/tcp"]
            assert len(mapping) == 1 and mapping[0]["HostIp"] == "127.0.0.1"
            return mapping[0]["HostPort"]

        def request(origin, path, expected=200, context=None, data=None):
            query = urllib.request.Request(origin + path, data=data)
            try:
                with urllib.request.urlopen(query, context=context, timeout=10) as response:
                    body, status = response.read(), response.status
            except urllib.error.HTTPError as error:
                body, status = error.read(), error.code
            assert status == expected, (path, status, expected)
            return body

        def probe():
            origin = "http://127.0.0.1:" + endpoint("server", 8080)
            assert request(origin, "/healthz").strip() == b"ok"
            assert request(origin, "/readyz").strip() == b"ready"
            meta = json.loads(request(origin, "/v1/meta"))
            assert meta["server_version"] == "0.1.10"
            assert meta["protocol_version"] == "1.5"
            assert meta["source_code_url"] == config.SOURCE
            assert meta["email_verification_required"] is True
            request(origin, "/v1/auth/me", 401)
            request(origin, "/account", 404)
            return meta

        try:
            cc("config", "--quiet")
            resolved = json.loads(cc("config", "--format", "json"))
            services = resolved["services"]
            assert services["server"]["image"] == config.IMAGE
            assert not services["postgres"].get("ports")
            assert resolved["networks"]["database"]["internal"] is True
            assert services["server"]["environment"]["CC_PUBLIC_URL"] == ""
            assert services["server"]["environment"]["CC_METRICS_LISTEN"] == "off"
            # `compose config` escapes dollars again for a reusable Compose document.
            assert services["server"]["environment"]["CC_SMTP_PASSWORD"].replace("$$", "$") == special_password
            assert services["server"]["environment"]["CC_REQUIRE_REQUEST_PROOF"] == "true"
            for flag in ("CC_OBJECT_SHARING_ENABLED", "CC_SHARED_GROUPS_ENABLED",
                         "CC_SHARED_SECRETS_ENABLED", "CC_SHARING_OWNER_ONLINE_ENROLLMENT_ENABLED"):
                assert services["server"]["environment"][flag] == "false"
            secret_values = [services["postgres"]["environment"]["POSTGRES_PASSWORD"],
                             services["server"]["environment"]["CC_DATABASE_PASSWORD"], special_password]
            checks.append("Compose configuration, immutable server, isolated database and ports")
            checks.append("SMTP password punctuation and backslashes survive Compose interpolation exactly")
            cli_directory = private / "cli-check"
            run([sys.executable, str(directory / "init-config.py"), "--directory",
                 str(cli_directory), "--domain", "sync.example.invalid", "--mail-disabled"])
            cli_configuration = cli_directory / "server.env"
            assert cli_configuration.stat().st_mode & 0o777 == 0o600
            cli_before = cli_configuration.read_bytes()
            second = subprocess.run([sys.executable, str(directory / "init-config.py"),
                                     "--directory", str(cli_directory), "--domain",
                                     "sync.example.invalid", "--mail-disabled"],
                                    capture_output=True, env=env)
            assert second.returncode != 0 and cli_configuration.read_bytes() == cli_before
            checks.append("documented init-config CLI creates configuration and refuses overwrite")
            no_tty_directory = private / "no-tty-check"
            no_tty = subprocess.run([sys.executable, str(directory / "init-config.py"),
                                    "--directory", str(no_tty_directory), "--domain",
                                    "sync.example.invalid"],
                                   input=("\nsmtp.example.invalid\n\n\ntest@example.invalid\n"
                                          + special_password + "\n").encode(),
                                   capture_output=True, env=env, start_new_session=True)
            assert no_tty.returncode != 0 and not (no_tty_directory / "server.env").exists()
            assert special_password.encode() not in no_tty.stdout + no_tty.stderr
            checks.append("hidden SMTP input fails closed without a controlling terminal; no password echo")
            cc("run", "--rm", "--no-deps", "caddy", "caddy", "validate", "--config", "/etc/caddy/Caddyfile")
            checks.append("documented caddy validate command")
            print("Starting disposable Compose project " + project, flush=True)
            cc("up", "-d", "--wait", "--wait-timeout", "180", "--pull", "never")
            meta = probe()
            server = inspect_service("server")
            runtime_env = dict(entry.split("=", 1) for entry in server["Config"]["Env"])
            assert runtime_env["CC_SMTP_PASSWORD"] == special_password
            assert server["Config"]["User"] == "65532:65532"
            assert server["HostConfig"]["ReadonlyRootfs"] is True
            assert server["State"]["Health"]["Status"] == "healthy"
            assert sql("SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication "
                       "FROM pg_roles WHERE rolname='consolecrypt';") == "f"
            assert sql("SELECT pg_get_userbyid(datdba) FROM pg_database "
                       "WHERE datname='consolecrypt';") == "consolecrypt"
            migrations = sql("SELECT string_agg(version::text, ',' ORDER BY version) "
                             "FROM _sqlx_migrations WHERE success;")
            assert migrations == "1,2,3,4,6,7"
            instance = sql("SELECT instance_id FROM sharing_instance;")
            marker = uuid.uuid4().hex
            sql("CREATE TABLE compose_verification_marker(value text PRIMARY KEY); "
                f"INSERT INTO compose_verification_marker VALUES ('{marker}');")
            checks.append("nonroot read-only server; database-owner role is not a superuser; migrations 1,2,3,4,6,7")
            checks.append("HTTP healthz/readyz/meta/auth; no website; strict proofs and sharing defaults")
            ca = private / "local-ca.crt"
            cc("cp", "caddy:/data/caddy/pki/authorities/local/root.crt", str(ca))
            context = ssl.create_default_context(cafile=str(ca))
            https = "https://localhost:" + endpoint("caddy", 443)
            for attempt in range(20):
                try:
                    assert request(https, "/readyz", context=context).strip() == b"ready"
                    break
                except urllib.error.URLError:
                    if attempt == 19:
                        raise
                    time.sleep(0.25)
            assert json.loads(request(https, "/v1/meta?probe=a%2Fb%20c", context=context)) == meta
            request(https, "/v1/events/ws", 401, context=context)
            for path in ("/", "/account", "/metrics", "/v1-unrelated"):
                request(https, path, 404, context=context)
            checks.append("Caddy HTTPS verified with explicit local CA; API routes and WebSocket auth reached; no website/metrics proxy")
            print("Healthy API and HTTPS proxy; checking backup and persistence.", flush=True)
            archive = cc("exec", "-T", "postgres", "pg_dump", "-U", "postgres", "-d", "consolecrypt",
                         "--format=custom", "--no-owner", "--no-acl")
            backup = private / "database.dump"
            descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(archive)
            listing = cc("exec", "-T", "postgres", "pg_restore", "--list", data=archive)
            assert b"sharing_instance" in listing and b"compose_verification_marker" in listing
            cc("exec", "-T", "postgres", "createdb", "-U", "postgres", "-O", "consolecrypt", "compose_restore_check")
            cc("exec", "-T", "postgres", "pg_restore", "-U", "postgres", "--role=consolecrypt",
               "-d", "compose_restore_check", "--exit-on-error", "--no-owner", "--no-acl", data=archive)
            assert sql("SELECT value FROM compose_verification_marker;", "compose_restore_check") == marker
            assert sql("SELECT instance_id FROM sharing_instance;", "compose_restore_check") == instance
            assert sql("SELECT count(*) FROM pg_tables WHERE schemaname='public';", "compose_restore_check") == sql(
                "SELECT count(*) FROM pg_tables WHERE schemaname='public';")
            cc("run", "--rm", "--no-deps", "-e",
               "CC_DATABASE_URL=postgres://consolecrypt@postgres:5432/compose_restore_check", "server", "migrate")
            checks.append("custom pg_dump/list/restore to separate empty DB; tables, marker and instance UUID match; pinned binary accepts restored schema")
            initial_logs = cc("logs", "--no-color")
            assert all(value.encode() not in initial_logs for value in secret_values)
            cc("down", "--timeout", "30")  # No -v: test the real persistent volumes.
            cc("up", "-d", "--wait", "--wait-timeout", "180", "--pull", "never")
            probe()
            assert sql("SELECT value FROM compose_verification_marker;") == marker
            assert sql("SELECT instance_id FROM sharing_instance;") == instance
            checks.append("Compose down/up preserves PostgreSQL volume and server instance UUID")
            logs = cc("logs", "--no-color")
            assert all(value.encode() not in logs for value in secret_values)
            checks.append("generated database passwords absent from container logs")
        finally:
            cc("down", "--volumes", "--remove-orphans", "--timeout", "30")
        checks.append("only disposable project containers/networks/volumes removed")
        print(json.dumps({"result": "PASS", "checks": checks, "meta": meta}, indent=2))


if __name__ == "__main__":
    main()
