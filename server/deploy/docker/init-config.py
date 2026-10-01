#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
"""Create a private first-install Compose environment; never overwrite it."""

import argparse
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import sys
import warnings

IMAGE = "registry.evsikov.net/publics/consolecrypt/server@sha256:7387d10a7e6e62d161e0154ce064a6ebe15999c338f33bb5df80691aca745301"
SOURCE = "https://git.evsikov.net/publics/consolecrypt/-/tree/960d0b6cf02367d2afa9813db7b8b3b5fd3ad7a2"


def quote(value):
    """Quote .env values, escaping backslashes/quotes and Compose interpolation."""
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Configuration values must be a single line")
    return json.dumps(value, ensure_ascii=False).replace("$", "$$")


def hostname(value):
    if len(value) > 253 or "." not in value or not all(
        re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", part)
        for part in value.split(".")
    ):
        raise argparse.ArgumentTypeError("Use a DNS hostname without scheme, path or port")
    return value.lower()


def prompt(label, default="", required=True, hidden=False):
    suffix = f" [{default}]" if default else ""
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        value = (getpass.getpass if hidden else input)(label + suffix + ": ") or default
    if required and not value:
        raise ValueError("A required value is empty")
    quote(value)
    return value


def create(directory, domain, mail):
    directory = directory.expanduser().resolve()
    source_root = Path(__file__).resolve().parents[3]
    if directory.is_relative_to(source_root):
        raise ValueError("Choose a private directory outside the source repository")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    target = directory / "server.env"
    settings = {
        "CC_DOMAIN": domain,
        "CC_HTTP_PORT": "8080",
        "CC_POSTGRES_ADMIN_PASSWORD": secrets.token_hex(32),
        "CC_DATABASE_PASSWORD": secrets.token_hex(32),
        "CC_SERVER_IMAGE": IMAGE,
        "CC_SOURCE_CODE_URL": SOURCE,
        "CC_RUN_MIGRATIONS": "true",
        "CC_REGISTRATION_OPEN": "true",
        **mail,
        "CC_OBJECT_SHARING_ENABLED": "false",
        "CC_SHARED_GROUPS_ENABLED": "false",
        "CC_SHARED_SECRETS_ENABLED": "false",
        "CC_SHARING_OWNER_ONLINE_ENROLLMENT_ENABLED": "false",
    }
    content = "# Private ConsoleCrypt Docker configuration. Do not commit or print.\n"
    content += "".join(f"{key}={quote(value)}\n" for key, value in settings.items())
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(content)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--domain", type=hostname, required=True)
    parser.add_argument("--mail-disabled", action="store_true",
                        help="Private installation: operator verifies email via admin CLI")
    args = parser.parse_args()
    if (args.directory.expanduser() / "server.env").exists():
        parser.error("server.env already exists; refusing to replace database credentials")
    mail = {"CC_MAIL_TRANSPORT": "disabled", "CC_MAIL_FROM": f"ConsoleCrypt <no-reply@{args.domain}>"}
    if not args.mail_disabled:
        mail.update({
            "CC_MAIL_TRANSPORT": "smtp",
            "CC_MAIL_FROM": prompt("Mail From", f"ConsoleCrypt <no-reply@{args.domain}>"),
            "CC_SMTP_HOST": prompt("SMTP hostname"),
            "CC_SMTP_PORT": prompt("SMTP port", "587"),
            "CC_SMTP_TLS": prompt("SMTP TLS mode (starttls or tls)", "starttls"),
            "CC_SMTP_USERNAME": prompt("SMTP username (empty for IP-authorized relay)", required=False),
            "CC_SMTP_PASSWORD": prompt("SMTP password (hidden; empty for IP-authorized relay)", required=False, hidden=True),
        })
        if mail["CC_SMTP_TLS"] not in ("starttls", "tls"):
            parser.error("Use starttls (usually 587) or tls (usually 465)")
        if not mail["CC_SMTP_PORT"].isdigit() or not 1 <= int(mail["CC_SMTP_PORT"]) <= 65535:
            parser.error("SMTP port must be between 1 and 65535")
    target = create(args.directory, args.domain, mail)
    print(f"Created {target} with mode 0600. Passwords were not printed.")


if __name__ == "__main__":
    try:
        main()
    except getpass.GetPassWarning:
        print("Hidden input is unavailable; use an interactive terminal. Configuration was not created.", file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, EOFError):
        # Do not echo input or OS exception details that may carry private values.
        print("Configuration was not created: check input, permissions and existing file.", file=sys.stderr)
        sys.exit(1)
