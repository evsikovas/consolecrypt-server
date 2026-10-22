# Enterprise sign-in test stands

Local Docker identity providers for the env-gated integration tests of the
sync server's enterprise sign-in mode:

| Stand | Container | Image (pinned by multi-arch index digest) | Ports (127.0.0.1 only) |
|---|---|---|---|
| OIDC | `cc-test-keycloak` | `quay.io/keycloak/keycloak:26.8.1@sha256:79c623a2…` | `58080` → 8080 (HTTP) |
| LDAP | `cc-test-samba` | `instantlinux/samba-dc:4.23.10-r0@sha256:7b569a7f…` | `50389` → 389 (LDAP + StartTLS), `50636` → 636 (LDAPS) |

Full digests are in `stands.py`. Both images ship linux/amd64 and linux/arm64.

> **TEST ONLY.** Every password, client secret and key below, and everything
> generated into `generated/`, is a fixed, public test constant. Never use any
> of it for a real deployment.

## Commands

```sh
python3 server/tests/stands/stands.py up    keycloak|samba|all   # start (reuses healthy containers), wait, provision
python3 server/tests/stands/stands.py check keycloak|samba|all   # self-checks (see below)
python3 server/tests/stands/stands.py down  keycloak|samba|all   # remove the containers (+ Samba volumes)
eval "$(python3 server/tests/stands/stands.py env)"              # export CC_TEST_* for running stands
```

`env` prints variables only for stands whose container is running (`env --all`
prints everything). Docker context defaults to `orbstack`; override with
`CC_STANDS_DOCKER_CONTEXT` (empty = current context). Python 3.9+, stdlib only.

Run the Rust tests:

```sh
eval "$(python3 server/tests/stands/stands.py env)"; cd server && CC_TEST_DATABASE_URL=postgres://postgres:cc-test-pg@127.0.0.1:55432/postgres CC_TEST_REQUIRE_DB=1 cargo test --test enterprise_oidc --test enterprise_ldap -- --nocapture
```

## Keycloak (`cc-test-keycloak`)

`start-dev --import-realm`, `KC_HOSTNAME=http://127.0.0.1:58080`, so the issuer
is always `http://127.0.0.1:58080/realms/cc-test`. Admin REST API:
`POST /realms/master/protocol/openid-connect/token` with `grant_type=password`,
`client_id=admin-cli`, `admin` / `cc-test-kc-admin` (TEST ONLY), then
`/admin/realms/cc-test/...` with the bearer token. Disable a user with
`PUT /admin/realms/cc-test/users/{id}` and `{"enabled": false}`.

Realm `cc-test` (`keycloak/realm-cc-test.json`):

- Client `consolecrypt-server`: confidential, secret `cc-test-oidc-secret` (TEST ONLY),
  standard flow only (implicit and direct access grants are off), PKCE S256 required,
  redirect URIs `http://127.0.0.1*` and `http://localhost*` (any port and path).
  Default scopes are basic, acr, profile, email, roles and web-origins; `offline_access` is optional.
  Refresh tokens are on.
- Mapper `groups` puts the group names (not paths) in the ID token, access token and userinfo.
  A user with no groups gets **no** `groups` claim at all. `acr` is `"1"`. `amr` is not emitted.
- Group `consolecrypt-users`. Users (password `Test-Password-1!`, TEST ONLY, verified email, no required actions):
  `alice` (alice@acme.test, in group), `bob` (bob@acme.test, no group), `carol` (carol@other.test, in group).
- `up` disables the `VERIFY_PROFILE` required action, so users that tests create without
  first or last names never see "Update Account Information".

### Scripted browser login (the way `check keycloak` and the Rust tests do it)

1. `GET {authorization_endpoint}?response_type=code&client_id=consolecrypt-server&redirect_uri=http://127.0.0.1:9/v1/auth/oidc/callback&scope=openid email profile&state=..&nonce=..&code_challenge=..&code_challenge_method=S256`
   returns `200` with the login page HTML.
2. Find `<form id="kc-form-login" ... action="http://127.0.0.1:58080/realms/cc-test/login-actions/authenticate?session_code=..&execution=..&client_id=consolecrypt-server&tab_id=..&client_data=..">`.
   The action is HTML-escaped (`&amp;`), so unescape it. Inputs are `username`, `password` and a hidden, empty `credentialId`.
3. `POST` the form (`application/x-www-form-urlencoded`: `username`, `password`, `credentialId=`) **with the cookies from step 1**.
   On success you get `302 Location: http://127.0.0.1:9/v1/auth/oidc/callback?state=..&session_state=..&iss=http%3A%2F%2F127.0.0.1%3A58080%2Frealms%2Fcc-test&code=..`.
   A wrong password returns `200` with the form again.
4. Exchange the code at the token endpoint with `client_secret_basic` plus `code_verifier`.

**Cookie quirk:** Keycloak sets `AUTH_SESSION_ID`, `KC_AUTH_SESSION_HASH` and `KC_RESTART` with
`Secure; SameSite=None` even over plain `http://127.0.0.1`. Browsers accept that because they treat
loopback as a secure context, but generic cookie jars (Python `http.cookiejar`, likely
`reqwest`/`cookie_store`) drop Secure cookies on `http`. If you do that, the POST fails with `400` and
the event log shows `cookie_not_found`. Keep the cookies by hand: copy each `Set-Cookie` `name=value`
and send it back in a `Cookie` header.

Without `code_challenge`, the authorization request redirects to the callback with
`error=invalid_request` (`Missing parameter: code_challenge_method`).

## Samba AD DC (`cc-test-samba`)

Realm `CCTEST.LOCAL`, NetBIOS `CCTEST`, DC `dc1.cctest.local`, base DN `DC=cctest,DC=local`.
The container runs with `--cap-add SYS_ADMIN`, because provisioning writes sysvol NT ACLs as xattrs.
Domain state lives in the volumes `cc-test-samba-etc` and `cc-test-samba-lib`, which `down` removes.
Password complexity, history and expiry are off, and the **account lockout threshold is 0**.

Samba keeps `ldap server require strong auth = yes`: a simple bind over plain `ldap://` without
StartTLS fails with resultCode 8 (`BindSimple: Transport encryption required.`).

TLS: `up` generates a test CA plus a server certificate into `generated/samba-tls/`
(`ca.pem`, `cert.pem`, `key.pem`; gitignored). The server certificate has
SAN `IP:127.0.0.1, DNS:localhost, DNS:dc1.cctest.local, DNS:dc1`. The container installs the
files to `/etc/cc-tls` (key mode 0600, owned by root) and adds `tls enabled/keyfile/certfile/cafile`
to `[global]`. LDAPS on 50636 and StartTLS on 50389 present the same certificate. Delete
`generated/` and run `up samba` to rotate it; the container is recreated.

All test passwords are TEST ONLY:

| Object | DN | Notes |
|---|---|---|
| Administrator | `CN=Administrator,CN=Users,DC=cctest,DC=local` | `Cc-Test-Admin-1!` |
| bind account | `CN=svc-consolecrypt,CN=Users,DC=cctest,DC=local` | `Svc-Test-Password-1!`, never expires |
| group | `CN=ConsoleCrypt,CN=Users,DC=cctest,DC=local` | members: alice, dave, ConsoleCrypt-Nested |
| nested group | `CN=ConsoleCrypt-Nested,CN=Users,DC=cctest,DC=local` | member of ConsoleCrypt; members: nina |
| alice | `CN=alice,CN=Users,DC=cctest,DC=local` | alice@acme.test, UPN alice@cctest.local |
| nina | `CN=nina,CN=Users,DC=cctest,DC=local` | nina@acme.test, only in the nested group |
| bob | `CN=bob,CN=Users,DC=cctest,DC=local` | bob@acme.test, no groups |
| dave | `CN=dave,CN=Users,DC=cctest,DC=local` | dave@acme.test, in ConsoleCrypt, **disabled** (bind gives rc 49, `data 533`) |

All users share the password `User-Test-Password-1!`. Their UPN is `<name>@cctest.local`,
`givenName` is the capitalised name and `sn` is `Tester`. Users bind by DN or by UPN.
A wrong password gives rc 49 with `data 52e`. The transitive filter
`(memberOf:1.2.840.113556.1.4.1941:=CN=ConsoleCrypt,CN=Users,DC=cctest,DC=local)` returns
alice, dave, nina and the nested group. Subtree searches from the base DN also return search
references (`ldap://cctest.local/CN=Configuration,...`, `DomainDnsZones`, `ForestDnsZones`),
which clients should ignore.

Changing fixtures from tests:

```sh
docker --context orbstack exec cc-test-samba samba-tool user disable <name>   # or: enable
docker --context orbstack exec cc-test-samba samba-tool user create <name> 'User-Test-Password-1!' --mail-address=<mail> --use-username-as-cn
docker --context orbstack exec cc-test-samba samba-tool group addmembers ConsoleCrypt <name>   # or: removemembers
```

Or over LDAPS as Administrator, set `userAccountControl` to `514` to disable an account or `512` to enable it.
`up samba` re-applies the fixture state: it creates missing objects, re-adds missing memberships,
enables alice, nina and bob, and disables dave. It does not remove extra objects or memberships that
tests add, so tests should clean those up themselves.

## Self-checks

`check keycloak` verifies discovery and the issuer, the admin REST API, the full code + PKCE
login for alice, carol and bob (groups claim, nonce, refresh token), that PKCE is enforced,
that a wrong password is rejected, and that direct grants are refused.

`check samba` verifies the TLS handshakes against `ca.pem`: LDAPS with the names `127.0.0.1`
and `localhost`, plus StartTLS. It also runs a minimal stdlib LDAP client for simple binds:
the bind account, Administrator, each user, the disabled user, binding by UPN, refusal on
plain LDAP, and no lockout after repeated failures. Finally it checks transitive group
membership through `ldbsearch` inside the container.
