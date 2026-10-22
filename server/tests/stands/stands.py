#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
"""Local Docker stands for the enterprise sign-in integration tests.

Two throwaway identity providers for the env-gated Rust tests
(`server/tests/enterprise_oidc.rs`, `server/tests/enterprise_ldap.rs`):

* cc-test-keycloak - Keycloak (OIDC) on http://127.0.0.1:58080, realm `cc-test`.
* cc-test-samba    - Samba AD DC (LDAP) on ldap://127.0.0.1:50389 (STARTTLS)
                     and ldaps://127.0.0.1:50636, domain CCTEST.LOCAL.

Usage:
    python3 server/tests/stands/stands.py up    keycloak|samba|all
    python3 server/tests/stands/stands.py check keycloak|samba|all
    python3 server/tests/stands/stands.py down  keycloak|samba|all
    eval "$(python3 server/tests/stands/stands.py env)"

EVERY PASSWORD, SECRET AND KEY IN THIS FILE (AND EVERYTHING WRITTEN TO
generated/) IS A FIXED, PUBLIC, TEST-ONLY CONSTANT. NEVER USE ANY OF IT
OUTSIDE THIS LOCAL STAND. All ports are bound to 127.0.0.1 only.

Python 3.9+, stdlib only. Needs `docker` and `openssl` on PATH.
"""
import argparse
import base64
import hashlib
import html.parser
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
GENERATED = HERE / "generated"
SAMBA_TLS_DIR = GENERATED / "samba-tls"

# Docker context. The stands are developed against OrbStack; override with
# CC_STANDS_DOCKER_CONTEXT ("" = docker's current context) for other hosts.
DOCKER_CONTEXT = os.environ.get("CC_STANDS_DOCKER_CONTEXT", "orbstack")
STAND_LABEL = "cc-test-stand"

# --------------------------------------------------------------------------
# Keycloak (OIDC). TEST ONLY credentials.
# --------------------------------------------------------------------------
KC_CONTAINER = "cc-test-keycloak"
# Pinned to the multi-arch OCI index digest (linux/amd64 + linux/arm64).
KC_IMAGE = (
    "quay.io/keycloak/keycloak:26.8.1"
    "@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244"
)
KC_PORT = 58080
KC_BASE = "http://127.0.0.1:%d" % KC_PORT
KC_REALM = "cc-test"
KC_ISSUER = "%s/realms/%s" % (KC_BASE, KC_REALM)
KC_ADMIN_USER = "admin"  # TEST ONLY bootstrap admin (master realm)
KC_ADMIN_PASSWORD = "cc-test-kc-admin"  # TEST ONLY
KC_CLIENT_ID = "consolecrypt-server"
KC_CLIENT_SECRET = "cc-test-oidc-secret"  # TEST ONLY
KC_USER_PASSWORD = "Test-Password-1!"  # TEST ONLY, all realm users
KC_GROUP = "consolecrypt-users"
KC_REALM_FILE = HERE / "keycloak" / "realm-cc-test.json"
KC_TEST_REDIRECT = "http://127.0.0.1:9/v1/auth/oidc/callback"

# --------------------------------------------------------------------------
# Samba AD DC (LDAP). TEST ONLY credentials.
# --------------------------------------------------------------------------
SAMBA_CONTAINER = "cc-test-samba"
# instantlinux/samba-dc (Alpine, Samba 4.23.10). Pinned to the multi-arch
# OCI index digest (linux/amd64, linux/arm64, linux/arm/v6, linux/arm/v7).
SAMBA_IMAGE = (
    "instantlinux/samba-dc:4.23.10-r0"
    "@sha256:7b569a7f21f86d9f6570de561dd07cb7e3d85ab57da7866b7006a9a932a8feb6"
)
SAMBA_VOLUMES = {
    "cc-test-samba-etc": "/etc/samba",
    "cc-test-samba-lib": "/var/lib/samba",
}
SAMBA_LDAP_PORT = 50389
SAMBA_LDAPS_PORT = 50636
SAMBA_HOSTNAME = "dc1"
SAMBA_REALM = "CCTEST.LOCAL"
SAMBA_DNS_DOMAIN = "cctest.local"
SAMBA_FQDN = "%s.%s" % (SAMBA_HOSTNAME, SAMBA_DNS_DOMAIN)
SAMBA_WORKGROUP = "CCTEST"
SAMBA_BASE_DN = "DC=cctest,DC=local"
SAMBA_USERS_DN = "CN=Users," + SAMBA_BASE_DN
SAMBA_ADMIN_DN = "CN=Administrator," + SAMBA_USERS_DN
SAMBA_ADMIN_PASSWORD = "Cc-Test-Admin-1!"  # TEST ONLY
SAMBA_SVC_USER = "svc-consolecrypt"
SAMBA_SVC_DN = "CN=%s,%s" % (SAMBA_SVC_USER, SAMBA_USERS_DN)
SAMBA_SVC_PASSWORD = "Svc-Test-Password-1!"  # TEST ONLY
SAMBA_USER_PASSWORD = "User-Test-Password-1!"  # TEST ONLY, all fixture users
SAMBA_GROUP = "ConsoleCrypt"
SAMBA_NESTED_GROUP = "ConsoleCrypt-Nested"
SAMBA_GROUP_DN = "CN=%s,%s" % (SAMBA_GROUP, SAMBA_USERS_DN)
SAMBA_NESTED_GROUP_DN = "CN=%s,%s" % (SAMBA_NESTED_GROUP, SAMBA_USERS_DN)
# username -> (mail, direct group or None, disabled)
SAMBA_USERS = {
    "alice": ("alice@acme.test", SAMBA_GROUP, False),
    "nina": ("nina@acme.test", SAMBA_NESTED_GROUP, False),
    "bob": ("bob@acme.test", None, False),
    "dave": ("dave@acme.test", SAMBA_GROUP, True),
}

# Wrapper around the image's entrypoint: writes the admin password secret the
# entrypoint expects, installs the TLS material with the 0600/root ownership
# Samba insists on, and adds a [global] TLS snippet. The image includes every
# /etc/samba/conf.d/*.conf at the end of smb.conf (inside [global]); the
# "00-" prefix keeps ours ahead of the [netlogon]/[sysvol] share snippets.
SAMBA_WRAPPER = r"""set -e
mkdir -p /run/secrets
umask 077
printf '%s' "$CC_TEST_SAMBA_ADMIN_PASSWORD" > /run/secrets/samba-admin-password
umask 022
mkdir -p /etc/cc-tls
install -o root -g root -m 600 /cc-tls-src/key.pem /etc/cc-tls/key.pem
install -o root -g root -m 644 /cc-tls-src/cert.pem /etc/cc-tls/cert.pem
install -o root -g root -m 644 /cc-tls-src/ca.pem /etc/cc-tls/ca.pem
mkdir -p -m 700 /etc/samba/conf.d
cat > /etc/samba/conf.d/00-cc-tls.conf <<'EOF'
[global]
	tls enabled = yes
	tls keyfile = /etc/cc-tls/key.pem
	tls certfile = /etc/cc-tls/cert.pem
	tls cafile = /etc/cc-tls/ca.pem
EOF
exec /usr/local/bin/entrypoint.sh
"""


class StandError(RuntimeError):
    pass


def log(msg: str) -> None:
    print("[stands] " + msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# docker helpers
# --------------------------------------------------------------------------
def docker_cmd(*args: str) -> List[str]:
    cmd = ["docker"]
    if DOCKER_CONTEXT:
        cmd += ["--context", DOCKER_CONTEXT]
    return cmd + list(args)


def docker(*args: str, check: bool = True, quiet: bool = False,
           input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(docker_cmd(*args), capture_output=True, text=True,
                          input=input_text)
    if check and proc.returncode != 0:
        raise StandError("docker %s failed (%d): %s" % (
            " ".join(args[:2]), proc.returncode,
            (proc.stderr or proc.stdout).strip()))
    if not quiet and proc.returncode != 0:
        log((proc.stderr or proc.stdout).strip())
    return proc


def container_info(name: str) -> Optional[dict]:
    proc = docker("inspect", "--type", "container", name, check=False, quiet=True)
    if proc.returncode != 0:
        return None
    return json.loads(proc.stdout)[0]


def container_running(name: str) -> bool:
    info = container_info(name)
    return bool(info and info["State"].get("Running"))


def remove_container(name: str) -> None:
    if container_info(name) is not None:
        log("removing container %s" % name)
        docker("rm", "-f", "-v", name)


def ensure_container(name: str, image: str, run_args: List[str],
                     probe) -> bool:
    """Start `name` unless it already runs `image` and `probe()` passes.

    Returns True when a fresh container was created.
    """
    info = container_info(name)
    if info is not None:
        if info["Config"].get("Image") != image:
            log("%s runs a different image, recreating" % name)
            remove_container(name)
        elif info["State"].get("Running"):
            if probe():
                log("%s already running and healthy, reusing" % name)
                return False
            log("%s running but not ready yet, waiting" % name)
            return False
        else:
            log("starting existing container %s" % name)
            docker("start", name)
            return False
    log("creating container %s from %s" % (name, image))
    docker("run", "-d", "--name", name, "--label", STAND_LABEL + "=" + name,
           *run_args)
    return True


def wait_for(what: str, probe, timeout: float, interval: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            if probe():
                log("%s: ready" % what)
                return
        except Exception as exc:  # noqa: BLE001 - probe errors mean "not yet"
            last_err = exc
        time.sleep(interval)
    raise StandError("timed out after %ds waiting for %s (last error: %s)" % (
        timeout, what, last_err))


# --------------------------------------------------------------------------
# HTTP helpers (no proxies, no automatic redirects)
# --------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def http_call(opener, url: str, data: Optional[Dict[str, str]] = None,
              headers: Optional[Dict[str, str]] = None, method: Optional[str] = None,
              body: Optional[bytes] = None, cookies: Optional[Dict[str, str]] = None):
    """Returns (status, headers: http.client.HTTPMessage, body).

    `cookies` is a plain name->value jar updated from Set-Cookie. Keycloak
    marks its login cookies `Secure` even on http://127.0.0.1 (browsers treat
    loopback as a secure context); http.cookiejar would drop them, so the
    jar is kept by hand and always sent.
    """
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        headers = dict(headers or {})
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    headers = dict(headers or {})
    if cookies:
        headers["Cookie"] = "; ".join("%s=%s" % kv for kv in cookies.items())
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(req, timeout=15) as resp:
            status, hdrs, data = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as err:
        status, hdrs, data = err.code, err.headers, err.read()
    if cookies is not None:
        for line in hdrs.get_all("Set-Cookie") or []:
            name, _, rest = line.partition("=")
            value = rest.split(";", 1)[0]
            if value:
                cookies[name.strip()] = value
            else:
                cookies.pop(name.strip(), None)
    return status, hdrs, data


def get_json(url: str, token: Optional[str] = None):
    headers = {"Authorization": "Bearer " + token} if token else {}
    status, _, body = http_call(http_opener(), url, headers=headers)
    if status != 200:
        raise StandError("GET %s -> %d %s" % (url, status, body[:200]))
    return json.loads(body)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


# --------------------------------------------------------------------------
# Keycloak
# --------------------------------------------------------------------------
def kc_probe() -> bool:
    try:
        conf = get_json(KC_ISSUER + "/.well-known/openid-configuration")
    except (OSError, StandError, ValueError):
        return False
    return conf.get("issuer") == KC_ISSUER


def kc_admin_token() -> str:
    status, _, body = http_call(
        http_opener(), KC_BASE + "/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli",
              "username": KC_ADMIN_USER, "password": KC_ADMIN_PASSWORD})
    if status != 200:
        raise StandError("admin-cli password grant -> %d %s" % (status, body[:300]))
    return json.loads(body)["access_token"]


def kc_admin(method: str, path: str, token: str, payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Authorization": "Bearer " + token}
    if body is not None:
        headers["Content-Type"] = "application/json"
    status, _, resp = http_call(http_opener(), KC_BASE + "/admin/realms/" + path,
                                headers=headers, method=method, body=body)
    if status >= 300:
        raise StandError("%s admin/%s -> %d %s" % (method, path, status, resp[:300]))
    return json.loads(resp) if resp.strip() else None


def kc_up() -> None:
    if not KC_REALM_FILE.is_file():
        raise StandError("missing realm file %s" % KC_REALM_FILE)
    ensure_container(KC_CONTAINER, KC_IMAGE, [
        "-p", "127.0.0.1:%d:8080" % KC_PORT,
        # TEST ONLY bootstrap admin.
        "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=" + KC_ADMIN_USER,
        "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + KC_ADMIN_PASSWORD,
        # Hostname v2: pin the frontend URL so the issuer is always
        # http://127.0.0.1:58080/realms/cc-test, whatever Host header is used.
        "-e", "KC_HOSTNAME=" + KC_BASE,
        "-e", "KC_HEALTH_ENABLED=true",
        "-v", "%s:/opt/keycloak/data/import/realm-cc-test.json:ro" % KC_REALM_FILE,
        KC_IMAGE, "start-dev", "--import-realm",
    ], kc_probe)
    wait_for("keycloak realm %s" % KC_REALM, kc_probe, timeout=240)
    kc_provision()


def kc_provision() -> None:
    token = kc_admin_token()
    # Users created later by the Rust tests may lack first/last name; never
    # let the "Update Account Information" (VERIFY_PROFILE) step interrupt
    # the scripted login.
    path = "%s/authentication/required-actions/VERIFY_PROFILE" % KC_REALM
    action = kc_admin("GET", path, token)
    if action.get("enabled") or action.get("defaultAction"):
        action["enabled"] = False
        action["defaultAction"] = False
        kc_admin("PUT", path, token, action)
        log("keycloak: disabled VERIFY_PROFILE required action")
    for user in kc_admin("GET", KC_REALM + "/users?briefRepresentation=false", token):
        if user.get("requiredActions"):
            user["requiredActions"] = []
            kc_admin("PUT", "%s/users/%s" % (KC_REALM, user["id"]), token, user)
    log("keycloak: provisioned (realm %s, issuer %s)" % (KC_REALM, KC_ISSUER))


class _FormParser(html.parser.HTMLParser):
    def __init__(self, form_id: str):
        super().__init__()
        self.form_id = form_id
        self.action = None
        self.inputs = {}
        self._inside = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == self.form_id:
            self._inside = True
            self.action = attrs.get("action")
        elif tag == "input" and self._inside and attrs.get("name"):
            self.inputs[attrs["name"]] = attrs.get("value") or ""

    def handle_endtag(self, tag):
        if tag == "form":
            self._inside = False


def kc_browser_login(username: str, password: str, scope: str = "openid email profile",
                     pkce: bool = True) -> dict:
    """Authorization code + PKCE flow the way a browser would do it.

    Returns {"location": <redirect>, "query": {...}, "verifier": ..., "nonce": ...}.
    """
    conf = get_json(KC_ISSUER + "/.well-known/openid-configuration")
    jar: Dict[str, str] = {}
    opener = http_opener()
    verifier = b64url(secrets.token_bytes(32))
    state = b64url(secrets.token_bytes(16))
    nonce = b64url(secrets.token_bytes(16))
    params = {
        "response_type": "code",
        "client_id": KC_CLIENT_ID,
        "redirect_uri": KC_TEST_REDIRECT,
        "scope": scope,
        "state": state,
        "nonce": nonce,
    }
    if pkce:
        params["code_challenge"] = b64url(hashlib.sha256(verifier.encode()).digest())
        params["code_challenge_method"] = "S256"
    url = conf["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)
    status, headers, body = http_call(opener, url, cookies=jar)
    if status in (302, 303):
        location = headers.get("Location", "")
        return {"location": location, "verifier": verifier, "nonce": nonce,
                "state": state, "login_page": False,
                "query": dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query))}
    if status != 200:
        raise StandError("auth endpoint -> %d %s" % (status, body[:300]))
    form = _FormParser("kc-form-login")
    form.feed(body.decode("utf-8", "replace"))
    if not form.action:
        raise StandError("login page has no form#kc-form-login")
    fields = dict(form.inputs)
    fields["username"] = username
    fields["password"] = password
    status, headers, body = http_call(opener, form.action, data=fields, cookies=jar)
    if status not in (302, 303):
        raise StandError("login POST -> %d (no redirect); body starts %r" % (
            status, body[:400]))
    location = headers.get("Location", "")
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query))
    return {"location": location, "query": query, "verifier": verifier,
            "nonce": nonce, "state": state, "login_page": True,
            "form_action": form.action, "form_fields": sorted(form.inputs)}


def kc_exchange(code: str, verifier: str) -> Tuple[int, dict]:
    conf = get_json(KC_ISSUER + "/.well-known/openid-configuration")
    basic = base64.b64encode(("%s:%s" % (
        urllib.parse.quote(KC_CLIENT_ID, safe=""),
        urllib.parse.quote(KC_CLIENT_SECRET, safe=""))).encode()).decode()
    status, _, body = http_call(
        http_opener(), conf["token_endpoint"],
        headers={"Authorization": "Basic " + basic},
        data={"grant_type": "authorization_code", "code": code,
              "redirect_uri": KC_TEST_REDIRECT, "code_verifier": verifier})
    return status, json.loads(body)


def kc_check() -> None:
    failures = []

    def expect(cond: bool, what: str) -> None:
        print(("  ok    " if cond else "  FAIL  ") + what)
        if not cond:
            failures.append(what)

    print("keycloak check (%s)" % KC_BASE)
    conf = get_json(KC_ISSUER + "/.well-known/openid-configuration")
    expect(conf.get("issuer") == KC_ISSUER, "issuer == %s" % KC_ISSUER)
    expect("S256" in conf.get("code_challenge_methods_supported", []),
           "discovery advertises S256 PKCE")
    print("        authorization_endpoint = %s" % conf.get("authorization_endpoint"))
    print("        token_endpoint         = %s" % conf.get("token_endpoint"))
    print("        jwks_uri               = %s" % conf.get("jwks_uri"))

    token = kc_admin_token()
    expect(True, "master admin-cli password grant as %s" % KC_ADMIN_USER)
    users = kc_admin("GET", KC_REALM + "/users?username=alice&exact=true", token)
    expect(len(users) == 1 and users[0].get("emailVerified"),
           "admin REST: GET /admin/realms/cc-test/users?username=alice")

    for user, want_groups in (("alice", [KC_GROUP]), ("carol", [KC_GROUP]), ("bob", [])):
        res = kc_browser_login(user, KC_USER_PASSWORD)
        q = res["query"]
        expect(res["login_page"] and res["location"].startswith(KC_TEST_REDIRECT + "?")
               and "code" in q and q.get("state") == res["state"],
               "%s: login form POST -> 302 %s?code=..&state=.." % (user, KC_TEST_REDIRECT))
        if user == "alice":
            print("        form action = %s" % res["form_action"].split("?")[0] + "?...")
            print("        form inputs = %s" % ", ".join(res["form_fields"]))
            print("        redirect query keys = %s" % ", ".join(sorted(q)))
        if "code" not in q:
            continue
        status, tok = kc_exchange(q["code"], res["verifier"])
        expect(status == 200 and "id_token" in tok,
               "%s: code exchange (client_secret_basic + PKCE) -> id_token" % user)
        if "id_token" not in tok:
            print("        token response: %s" % tok)
            continue
        expect("refresh_token" in tok, "%s: refresh_token issued" % user)
        claims = jwt_claims(tok["id_token"])
        expect(claims.get("iss") == KC_ISSUER and claims.get("aud") in (
            KC_CLIENT_ID, [KC_CLIENT_ID]) and claims.get("nonce") == res["nonce"],
            "%s: id_token iss/aud/nonce" % user)
        expect(claims.get("preferred_username") == user
               and claims.get("email_verified") is True and "@" in claims.get("email", ""),
               "%s: preferred_username/email/email_verified" % user)
        expect(sorted(claims.get("groups") or []) == want_groups,
               "%s: groups claim == %s (got %r)" % (user, want_groups, claims.get("groups")))
        if user == "alice":
            shown = {k: claims.get(k) for k in (
                "iss", "aud", "azp", "sub", "preferred_username", "email",
                "email_verified", "groups", "acr", "amr", "auth_time", "sid")}
            print("        alice id_token claims: %s" % json.dumps(shown))

    # PKCE is mandatory for this client.
    res = kc_browser_login("alice", KC_USER_PASSWORD, pkce=False)
    q = res["query"]
    expect(not res["login_page"] and q.get("error") == "invalid_request",
           "auth request without code_challenge rejected (error=%s, %s)" % (
               q.get("error"), q.get("error_description")))
    # Wrong password stays on the login page (no redirect).
    try:
        kc_browser_login("alice", "wrong-password")
        expect(False, "wrong password rejected")
    except StandError as exc:
        expect("login POST -> 200" in str(exc), "wrong password -> login page again (200)")
    # Direct access grants are off.
    status, _, body = http_call(
        http_opener(), conf["token_endpoint"],
        data={"grant_type": "password", "client_id": KC_CLIENT_ID,
              "client_secret": KC_CLIENT_SECRET, "username": "alice",
              "password": KC_USER_PASSWORD, "scope": "openid"})
    expect(status in (400, 401) and b"unauthorized_client" in body,
           "direct access grant refused (%d)" % status)

    if failures:
        raise StandError("keycloak check: %d failure(s)" % len(failures))
    print("keycloak check: all good")


# --------------------------------------------------------------------------
# TLS material for Samba
# --------------------------------------------------------------------------
def ensure_samba_tls() -> bool:
    """Create a test CA + server cert. Returns True when (re)generated."""
    ca, cert, key = (SAMBA_TLS_DIR / n for n in ("ca.pem", "cert.pem", "key.pem"))
    if ca.is_file() and cert.is_file() and key.is_file():
        return False
    if shutil.which("openssl") is None:
        raise StandError("openssl not found on PATH")
    SAMBA_TLS_DIR.mkdir(parents=True, exist_ok=True)
    work = SAMBA_TLS_DIR
    ca_key = work / "ca-key.pem"
    ext = work / "server-ext.cnf"
    ext.write_text(
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid, issuer\n"
        "subjectAltName = IP:127.0.0.1, DNS:localhost, DNS:%s, DNS:%s\n"
        % (SAMBA_FQDN, SAMBA_HOSTNAME))

    def run(*args: str) -> None:
        proc = subprocess.run(["openssl", *args], capture_output=True, text=True)
        if proc.returncode != 0:
            raise StandError("openssl %s failed: %s" % (args[0], proc.stderr.strip()))

    log("generating TEST ONLY CA and Samba server certificate in %s" % work)
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "3650", "-keyout", str(ca_key), "-out", str(ca),
        "-subj", "/O=ConsoleCrypt TEST ONLY/CN=ConsoleCrypt test stand CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    csr = work / "server.csr"
    run("req", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-keyout", str(key), "-out", str(csr),
        "-subj", "/O=ConsoleCrypt TEST ONLY/CN=%s" % SAMBA_FQDN)
    run("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
        "-CAcreateserial", "-days", "3650", "-sha256",
        "-extfile", str(ext), "-out", str(cert))
    csr.unlink()
    for p in (key, ca_key):
        os.chmod(p, 0o600)
    return True


def pem_der(path: Path) -> bytes:
    return ssl.PEM_cert_to_DER_cert(path.read_text())


def tls_peer_der(port: int, server_hostname: str, starttls: bool = False) -> bytes:
    ctx = ssl.create_default_context(cafile=str(SAMBA_TLS_DIR / "ca.pem"))
    ctx.check_hostname = True
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        if starttls:
            ldap_starttls(raw)
        with ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
            return tls.getpeercert(binary_form=True)


# --------------------------------------------------------------------------
# Minimal LDAP (BER) client: simple bind + StartTLS, enough for self-checks.
# --------------------------------------------------------------------------
def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(content)) + content


def _ber_int(v: int) -> bytes:
    return _tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def _parse_tlv(buf: bytes, off: int) -> Tuple[int, bytes, int]:
    tag = buf[off]
    n = buf[off + 1]
    off += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[off:off + k], "big")
        off += k
    return tag, buf[off:off + n], off + n


def _recv_exact(sock, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise StandError("LDAP connection closed")
        out += chunk
    return out


def _ldap_roundtrip(sock, msg: bytes) -> Tuple[int, int, str]:
    sock.sendall(msg)
    head = _recv_exact(sock, 2)
    n = head[1]
    extra = b""
    if n & 0x80:
        extra = _recv_exact(sock, n & 0x7F)
        n = int.from_bytes(extra, "big")
    full = head + extra + _recv_exact(sock, n)
    _, seq, _ = _parse_tlv(full, 0)
    _, _, off = _parse_tlv(seq, 0)  # messageID
    op_tag, op, _ = _parse_tlv(seq, off)
    _, code, off = _parse_tlv(op, 0)  # resultCode (ENUMERATED)
    _, _, off = _parse_tlv(op, off)  # matchedDN
    _, diag, _ = _parse_tlv(op, off)  # diagnosticMessage
    return op_tag, int.from_bytes(code, "big"), diag.decode("utf-8", "replace")


def ldap_starttls(sock) -> None:
    req = _tlv(0x30, _ber_int(1) + _tlv(0x77, _tlv(0x80, b"1.3.6.1.4.1.1466.20037")))
    tag, code, diag = _ldap_roundtrip(sock, req)
    if tag != 0x78 or code != 0:
        raise StandError("StartTLS refused: %d %s" % (code, diag))


def ldap_simple_bind(mode: str, dn: str, password: str) -> Tuple[int, str]:
    """mode: ldaps | starttls | plain. Returns (resultCode, diagnosticMessage)."""
    port = SAMBA_LDAPS_PORT if mode == "ldaps" else SAMBA_LDAP_PORT
    ctx = ssl.create_default_context(cafile=str(SAMBA_TLS_DIR / "ca.pem"))
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        sock = raw
        if mode == "starttls":
            ldap_starttls(raw)
        if mode in ("ldaps", "starttls"):
            sock = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
        bind = _tlv(0x30, _ber_int(2) + _tlv(0x60, _ber_int(3) + _tlv(
            0x04, dn.encode()) + _tlv(0x80, password.encode())))
        _, code, diag = _ldap_roundtrip(sock, bind)
        return code, diag
    finally:
        raw.close()


# --------------------------------------------------------------------------
# Samba
# --------------------------------------------------------------------------
def samba_exec(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return docker("exec", SAMBA_CONTAINER, *args, check=check, quiet=True)


def samba_tls_probe() -> bool:
    try:
        return tls_peer_der(SAMBA_LDAPS_PORT, "127.0.0.1") == pem_der(
            SAMBA_TLS_DIR / "cert.pem")
    except (OSError, ssl.SSLError):
        return False


def samba_probe() -> bool:
    if not samba_tls_probe():
        return False
    return samba_exec("samba-tool", "user", "show", "Administrator",
                      check=False).returncode == 0


def samba_up() -> None:
    regenerated = ensure_samba_tls()
    if regenerated and container_info(SAMBA_CONTAINER) is not None:
        log("TLS material regenerated, recreating %s" % SAMBA_CONTAINER)
        samba_down()
    info = container_info(SAMBA_CONTAINER)
    if info is not None and info["State"].get("Running") and not samba_tls_probe():
        # Running but presenting another certificate (e.g. generated/ wiped).
        time.sleep(5)
        if not samba_tls_probe():
            log("%s does not present the generated certificate, recreating"
                % SAMBA_CONTAINER)
            samba_down()
    run_args = [
        "--hostname", SAMBA_HOSTNAME,
        # Provisioning writes NT ACLs on sysvol as security.NTACL xattrs,
        # which needs CAP_SYS_ADMIN (otherwise NT_STATUS_ACCESS_DENIED).
        "--cap-add", "SYS_ADMIN",
        "-p", "127.0.0.1:%d:389" % SAMBA_LDAP_PORT,
        "-p", "127.0.0.1:%d:636" % SAMBA_LDAPS_PORT,
        "-e", "REALM=" + SAMBA_DNS_DOMAIN,
        "-e", "WORKGROUP=" + SAMBA_WORKGROUP,
        "-e", "NETBIOS_NAME=" + SAMBA_HOSTNAME.upper(),
        "-e", "TZ=UTC",
        # TEST ONLY Administrator password (consumed by the wrapper).
        "-e", "CC_TEST_SAMBA_ADMIN_PASSWORD=" + SAMBA_ADMIN_PASSWORD,
        "-v", "%s:/cc-tls-src:ro" % SAMBA_TLS_DIR,
    ]
    for vol, path in SAMBA_VOLUMES.items():
        run_args += ["-v", "%s:%s" % (vol, path)]
    run_args += ["--entrypoint", "/bin/sh", SAMBA_IMAGE, "-c", SAMBA_WRAPPER]
    ensure_container(SAMBA_CONTAINER, SAMBA_IMAGE, run_args, samba_probe)
    wait_for("samba AD DC (ldaps + sam.ldb)", samba_probe, timeout=300, interval=3)
    samba_provision()


def samba_object_exists(kind: str, name: str) -> bool:
    return samba_exec("samba-tool", kind, "show", name, check=False).returncode == 0


def samba_provision() -> None:
    # Test stand: no complexity, no expiry, no history, and NO LOCKOUT, so
    # repeated failed binds in tests never lock an account.
    samba_exec("samba-tool", "domain", "passwordsettings", "set",
               "--complexity=off", "--history-length=0", "--min-pwd-age=0",
               "--max-pwd-age=0", "--account-lockout-threshold=0")
    if not samba_object_exists("user", SAMBA_SVC_USER):
        samba_exec("samba-tool", "user", "create", SAMBA_SVC_USER, SAMBA_SVC_PASSWORD,
                   "--description=ConsoleCrypt LDAP bind account (TEST ONLY)")
        log("samba: created %s" % SAMBA_SVC_DN)
    for group in (SAMBA_GROUP, SAMBA_NESTED_GROUP):
        if not samba_object_exists("group", group):
            samba_exec("samba-tool", "group", "add", group)
            log("samba: created group %s" % group)
    members = samba_exec("samba-tool", "group", "listmembers", SAMBA_GROUP).stdout.split()
    if SAMBA_NESTED_GROUP not in members:
        samba_exec("samba-tool", "group", "addmembers", SAMBA_GROUP, SAMBA_NESTED_GROUP)
    for user, (mail, group, disabled) in SAMBA_USERS.items():
        if not samba_object_exists("user", user):
            samba_exec("samba-tool", "user", "create", user, SAMBA_USER_PASSWORD,
                       "--mail-address=" + mail,
                       "--given-name=" + user.capitalize(), "--surname=Tester",
                       "--use-username-as-cn")
            log("samba: created user %s" % user)
        if group:
            members = samba_exec("samba-tool", "group", "listmembers", group).stdout.split()
            if user not in members:
                samba_exec("samba-tool", "group", "addmembers", group, user)
        if disabled:
            samba_exec("samba-tool", "user", "disable", user)
        else:
            samba_exec("samba-tool", "user", "enable", user)
    samba_exec("samba-tool", "user", "setexpiry", "--noexpiry", SAMBA_SVC_USER)
    log("samba: provisioned (base %s)" % SAMBA_BASE_DN)


def samba_user_dn(user: str) -> str:
    # Created with --use-username-as-cn, so CN == sAMAccountName.
    return "CN=%s,%s" % (user, SAMBA_USERS_DN)


def samba_check() -> None:
    failures = []

    def expect(cond: bool, what: str) -> None:
        print(("  ok    " if cond else "  FAIL  ") + what)
        if not cond:
            failures.append(what)

    print("samba check (ldaps://127.0.0.1:%d, ldap://127.0.0.1:%d)" % (
        SAMBA_LDAPS_PORT, SAMBA_LDAP_PORT))
    want = pem_der(SAMBA_TLS_DIR / "cert.pem")
    for name in ("127.0.0.1", "localhost"):
        try:
            got = tls_peer_der(SAMBA_LDAPS_PORT, name)
            expect(got == want, "LDAPS handshake verifies against ca.pem (SNI/name %s)" % name)
        except (OSError, ssl.SSLError) as exc:
            expect(False, "LDAPS handshake (%s): %s" % (name, exc))
    try:
        got = tls_peer_der(SAMBA_LDAP_PORT, "127.0.0.1", starttls=True)
        expect(got == want, "StartTLS on 389 presents the same certificate")
    except (OSError, ssl.SSLError, StandError) as exc:
        expect(False, "StartTLS handshake: %s" % exc)

    for mode in ("ldaps", "starttls"):
        code, diag = ldap_simple_bind(mode, SAMBA_SVC_DN, SAMBA_SVC_PASSWORD)
        expect(code == 0, "%s simple bind as %s (rc=%d %s)" % (mode, SAMBA_SVC_DN, code, diag))
    code, diag = ldap_simple_bind("plain", SAMBA_SVC_DN, SAMBA_SVC_PASSWORD)
    expect(code == 8, "plain-LDAP simple bind refused: strongerAuthRequired (rc=%d %s)"
           % (code, diag))
    code, _ = ldap_simple_bind("ldaps", SAMBA_ADMIN_DN, SAMBA_ADMIN_PASSWORD)
    expect(code == 0, "ldaps bind as %s" % SAMBA_ADMIN_DN)
    for user, (_, _, disabled) in SAMBA_USERS.items():
        dn = samba_user_dn(user)
        code, diag = ldap_simple_bind("ldaps", dn, SAMBA_USER_PASSWORD)
        if disabled:
            expect(code == 49 and "533" in diag,
                   "%s (disabled) bind refused rc=49 data 533 (rc=%d %s)" % (user, code, diag))
        else:
            expect(code == 0, "%s bind as %s (rc=%d %s)" % (user, dn, code, diag))
    code, diag = ldap_simple_bind("ldaps", "alice@" + SAMBA_DNS_DOMAIN, SAMBA_USER_PASSWORD)
    expect(code == 0, "alice bind by UPN alice@%s (rc=%d)" % (SAMBA_DNS_DOMAIN, code))
    for _ in range(6):
        code, diag = ldap_simple_bind("ldaps", samba_user_dn("bob"), "wrong-password")
    expect(code == 49, "wrong password -> rc=49 (%s)" % diag)
    code, _ = ldap_simple_bind("ldaps", samba_user_dn("bob"), SAMBA_USER_PASSWORD)
    expect(code == 0, "bob still binds after 6 failures (no lockout)")

    pw = samba_exec("samba-tool", "domain", "passwordsettings", "show").stdout
    expect("Account lockout threshold (attempts): 0" in pw, "account lockout threshold 0")

    proc = samba_exec(
        "ldbsearch", "-H", "/var/lib/samba/private/sam.ldb", "-b", SAMBA_BASE_DN,
        "(memberOf:1.2.840.113556.1.4.1941:=%s)" % SAMBA_GROUP_DN, "sAMAccountName")
    found = sorted(line.split(": ", 1)[1] for line in proc.stdout.splitlines()
                   if line.startswith("sAMAccountName: "))
    expect(found == sorted([SAMBA_NESTED_GROUP, "alice", "dave", "nina"]),
           "transitive members of %s = %s" % (SAMBA_GROUP, found))
    proc = samba_exec("ldbsearch", "-H", "/var/lib/samba/private/sam.ldb", "-b",
                      SAMBA_BASE_DN, "(sAMAccountName=alice)", "dn", "mail",
                      "userPrincipalName", "memberOf", "userAccountControl")
    print("        " + "\n        ".join(
        line for line in proc.stdout.splitlines() if line and not line.startswith("#")))

    if shutil.which("ldapsearch"):
        # Informational only. macOS' /usr/bin/ldapsearch ignores LDAPTLS_CACERT
        # (it trusts the keychain), so certificate verification is skipped
        # here; the handshakes above already verified the chain.
        env = dict(os.environ, LDAPTLS_CACERT=str(SAMBA_TLS_DIR / "ca.pem"),
                   LDAPTLS_REQCERT="never")
        proc = subprocess.run(
            ["ldapsearch", "-LLL", "-x", "-H", "ldaps://127.0.0.1:%d" % SAMBA_LDAPS_PORT,
             "-D", SAMBA_SVC_DN, "-w", SAMBA_SVC_PASSWORD, "-b", SAMBA_BASE_DN,
             "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=%s))" % SAMBA_GROUP_DN,
             "dn"],
            capture_output=True, text=True, env=env)
        dns = [l[4:] for l in proc.stdout.splitlines() if l.startswith("dn: ")]
        print("  info  host ldapsearch (svc bind, ldaps, in-chain filter): rc=%d %s" % (
            proc.returncode, dns or proc.stderr.strip()))

    if failures:
        raise StandError("samba check: %d failure(s)" % len(failures))
    print("samba check: all good")


def samba_down() -> None:
    remove_container(SAMBA_CONTAINER)
    for vol in SAMBA_VOLUMES:
        if docker("volume", "inspect", vol, check=False, quiet=True).returncode == 0:
            log("removing volume %s" % vol)
            docker("volume", "rm", vol)


def kc_down() -> None:
    remove_container(KC_CONTAINER)


# --------------------------------------------------------------------------
# env
# --------------------------------------------------------------------------
def env_lines(include_all: bool) -> List[str]:
    out = []
    if include_all or container_running(KC_CONTAINER):
        out += [
            ("CC_TEST_KEYCLOAK", "1"),
            ("CC_TEST_KEYCLOAK_ISSUER", KC_ISSUER),
            ("CC_TEST_KEYCLOAK_CLIENT_ID", KC_CLIENT_ID),
            ("CC_TEST_KEYCLOAK_CLIENT_SECRET", KC_CLIENT_SECRET),
            ("CC_TEST_KEYCLOAK_ADMIN_URL", KC_BASE),
            ("CC_TEST_KEYCLOAK_REALM", KC_REALM),
            ("CC_TEST_KEYCLOAK_ADMIN_USER", KC_ADMIN_USER),
            ("CC_TEST_KEYCLOAK_ADMIN_PASSWORD", KC_ADMIN_PASSWORD),
            ("CC_TEST_KEYCLOAK_USER_PASSWORD", KC_USER_PASSWORD),
            ("CC_TEST_KEYCLOAK_GROUP", KC_GROUP),
        ]
    if include_all or container_running(SAMBA_CONTAINER):
        out += [
            ("CC_TEST_SAMBA", "1"),
            ("CC_TEST_SAMBA_LDAPS_URL", "ldaps://127.0.0.1:%d" % SAMBA_LDAPS_PORT),
            ("CC_TEST_SAMBA_LDAP_URL", "ldap://127.0.0.1:%d" % SAMBA_LDAP_PORT),
            ("CC_TEST_SAMBA_CA_FILE", str(SAMBA_TLS_DIR / "ca.pem")),
            ("CC_TEST_SAMBA_BIND_DN", SAMBA_SVC_DN),
            ("CC_TEST_SAMBA_BIND_PASSWORD", SAMBA_SVC_PASSWORD),
            ("CC_TEST_SAMBA_BASE_DN", SAMBA_BASE_DN),
            ("CC_TEST_SAMBA_USERS_DN", SAMBA_USERS_DN),
            ("CC_TEST_SAMBA_GROUP_DN", SAMBA_GROUP_DN),
            ("CC_TEST_SAMBA_NESTED_GROUP_DN", SAMBA_NESTED_GROUP_DN),
            ("CC_TEST_SAMBA_ADMIN_DN", SAMBA_ADMIN_DN),
            ("CC_TEST_SAMBA_ADMIN_PASSWORD", SAMBA_ADMIN_PASSWORD),
            ("CC_TEST_SAMBA_USER_PASSWORD", SAMBA_USER_PASSWORD),
            ("CC_TEST_SAMBA_CONTAINER", SAMBA_CONTAINER),
        ]
    return ["export %s=%s" % (k, _shell_quote(v)) for k, v in out]


def _shell_quote(v: str) -> str:
    return "'" + v.replace("'", "'\"'\"'") + "'"


# --------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("up", "down", "check"):
        p = sub.add_parser(name)
        p.add_argument("stand", choices=("keycloak", "samba", "all"))
    p = sub.add_parser("env", help="print export lines for the running stands")
    p.add_argument("--all", action="store_true",
                   help="print every variable even if a stand is not running")
    args = ap.parse_args(argv)

    if args.cmd == "env":
        print("\n".join(env_lines(args.all)))
        return 0
    stands = ("keycloak", "samba") if args.stand == "all" else (args.stand,)
    actions = {
        "up": {"keycloak": kc_up, "samba": samba_up},
        "down": {"keycloak": kc_down, "samba": samba_down},
        "check": {"keycloak": kc_check, "samba": samba_check},
    }[args.cmd]
    try:
        for stand in stands:
            actions[stand]()
    except StandError as exc:
        log("ERROR: %s" % exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
