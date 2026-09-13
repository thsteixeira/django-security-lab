# Lab 14 — Password Reset Flows

Companion lab for the blog post
**[Password Reset Flows](https://thiagoteixeira.tech/blog/)** *(link finalised on publication)*.

| | |
|---|---|
| **OWASP** | A07:2025 — Authentication Failures |
| **CWE** | CWE-640 — Weak Password Recovery Mechanism · CWE-613 — Insufficient Session Expiration · CWE-204 — Observable Response Discrepancy |
| **ASVS** | V2.5.1 — reset tokens are time-limited and single-use · V2.5.6 — recovery does not reveal whether an account exists |
| **NIST** | SP 800-63B-4 §5.1.3 — an out-of-band secret **SHALL** be valid for a limited time and **SHALL** be single-use |
| **Detection** | **No rule in any tier distinguishes the bug from the fix.** Bandit: 5 findings, none in a view. Semgrep curated packs: 2 findings, the *same rule on both halves*. Semgrep audit/registry tier: 17 findings, and the 10 that reach the two confirm views land in **matching pairs**. So this lab ships a **custom rule** — [`rules/password_reset.yaml`](../../rules/password_reset.yaml). See [`scans/`](scans/) |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The four views

| View | File | What it does |
|---|---|---|
| Vulnerable — request | [`views_vulnerable.py`](views_vulnerable.py) | issues a `uuid4` token into a `ResetToken` row and builds the link with `request.build_absolute_uri()`. Answers **404** for an unknown address and **200** for a known one |
| Vulnerable — confirm | [`views_vulnerable.py`](views_vulnerable.py) | looks the token up, checks it belongs to the user, and calls `set_password()`. Never calls `check_token()` |
| Secure — request | [`views_secure.py`](views_secure.py) | `default_token_generator.make_token(user)`, link built from `RESET_BASE_URL`, and the **same response either way** |
| Secure — confirm | [`views_secure.py`](views_secure.py) | `default_token_generator.check_token(user, token)` before the write |

The privilege boundary is a fifth endpoint, [`/password-reset/vault/`](views_vault.py),
which serves **dave's** stored recovery codes (the flag) only to a session
authenticated as dave. Completing a reset you had no right to complete *is* the
exploit.

## The bug is not the token — it is everything the token does not know

`uuid4` is unguessable. That is not in dispute, and it is why "use a longer random
string" is not the fix.

The problem is that a random string in a row knows nothing about itself. Whether
it is too old, whether it was already spent, whether the account has moved on
since it was issued — every one of those is a question somebody has to remember to
ask, in code, at the right moment. [`models.py`](models.py) records enough to
answer two of them:

```python
created = models.DateTimeField(default=timezone.now)
used_at = models.DateTimeField(null=True, blank=True)
```

Both columns are written faithfully. `confirm()` even sets `used_at` itself,
immediately after changing the password. **Neither is ever read by a branch that
refuses anything.** That is what makes this the realistic shape of the bug rather
than a straw man: the data model is not missing anything, and a schema review
would pass it. The check is what is missing.

Django's `PasswordResetTokenGenerator` answers all three questions without a
branch, because the answers are *inside the token*. Its hash input is the user's
pk, **password hash**, `last_login`, email and a timestamp, HMAC'd with
`SECRET_KEY`:

- it **expires**, because the timestamp is hashed in and `check_token` compares it against `PASSWORD_RESET_TIMEOUT` (3 days by default);
- it **self-retires on use**, because completing a reset changes `user.password`, which changes the hash input — the token that just worked stops verifying;
- it **self-retires on login**, because `last_login` is in there too.

So the secure view does not maintain `used_at` correctly. It has no `used_at` at
all, which is a stronger outcome than remembering to check one.

## Why dave's password is strong

The seeded victim's passphrase is long, unguessable and in no wordlist, and
`tests.py` asserts that four plausible guesses all fail. That is deliberate: this
lab must not be quietly winnable as a weak-password lab — that is
[Lab 13](../post_13_weak_passwords/). The reset flow is the only way in, which is
the entire point.

What the seed plants beside him is a `ResetToken` **issued 400 days ago**. It
stands in for the thing that actually happens to reset links: they are ordinary
URLs, and ordinary URLs end up in reverse-proxy access logs, browser history,
corporate TLS-inspection appliances, `Referer` headers sent from the confirmation
page, and mailbox backups that outlive the account. The interesting question was
never "can an attacker guess the token." It is **how long a token that leaked stays
valuable**, and this flow answers: forever.

## Host-header poisoning, and the control that actually stops it

The vulnerable request view builds its link with `request.build_absolute_uri()`.
The host in that URL is whatever the client said it was — so a `Host: evil.test`
header rewrites the domain of a link your server then emails to a victim, who
clicks their own reset link and hands the token to whoever is listening there.

In this lab that attack **does not land**, and the reason is worth seeing:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: evil.test' \
     -X POST -d 'email=dave@example.test' \
     http://127.0.0.1:8000/password-reset/vulnerable/request/
# 400
```

The request never reaches the view. Django validates `Host` against
`ALLOWED_HOSTS` and raises `DisallowedHost` first. **`ALLOWED_HOSTS` is the
control** — a framework setting, not anything in the view — and
`test_allowed_hosts_is_what_actually_blocks_the_poisoned_host` asserts exactly
that, unoverridden.

Three tests then set `ALLOWED_HOSTS = ["*"]`, which is the single most common way
real projects switch that backstop off. With it gone, the two link builders can
finally be compared:

| View | Link in the mailed message |
|---|---|
| `views_vulnerable.py` | `http://evil.test/password-reset/vulnerable/confirm/…` — **poisoned** |
| `views_secure.py` | `http://127.0.0.1:8000/password-reset/secure/confirm/…` — unchanged |

That is the argument for taking the host from configuration: the link stays
correct even when `ALLOWED_HOSTS` is wrong. Two independent controls, and the app
should not need both to be right.

## Account enumeration

The vulnerable request view answers **404 / "no account with that email"** for an
address nobody has registered and **200 / "reset email sent"** for one that exists.
That turns a password-reset form into a membership oracle for any list of email
addresses someone cares to POST.

The secure view returns one string, with one status, both ways — and only sends
mail in one of them.

It does **not** close the timing side channel: the matching branch hashes a token
and sends an email, so it takes measurably longer. Django's own
`PasswordResetForm` has the same property. Closing it properly means moving the
send to a queue so both paths return immediately, which is a real fix and out of
scope for this lab; it is called out here so the uniform response is not mistaken
for a complete one.

## Run it

```bash
docker compose up --build        # migrates, seeds, serves on 127.0.0.1:8000
```

The seed prints the leaked link, including the `uidb64` for **this** database:

```
passwordreset: seeded victim 'dave' (strong password) + a reset token issued 400 days ago
+ flag vault item. Leaked link: /password-reset/vulnerable/confirm/<uidb64>/6f1c1e2a-9b7d-4a3f-8c21-0d5e7a9b4c33/
```

Read the `uidb64` from that line rather than copying one from this README — it
encodes dave's primary key, which differs between databases. The token itself is
a fixed constant, so it is safe to paste.

## Exploit the pair from the command line

```bash
UID64=<from the seed log>
TOKEN=6f1c1e2a-9b7d-4a3f-8c21-0d5e7a9b4c33
BASE=http://127.0.0.1:8000

# 1. The request endpoint answers a question it was not asked.
curl -s -X POST -d 'email=nobody@example.test' $BASE/password-reset/vulnerable/request/
# no account with that email                       [HTTP 404]
curl -s -X POST -d 'email=dave@example.test'   $BASE/password-reset/vulnerable/request/
# reset email sent                                 [HTTP 200]

# The secure one does not.
curl -s -X POST -d 'email=nobody@example.test' $BASE/password-reset/secure/request/
curl -s -X POST -d 'email=dave@example.test'   $BASE/password-reset/secure/request/
# if an account exists for that address, a reset link has been sent   [HTTP 200, both]

# 2. Replay the 400-day-old leaked token. No guessing, no throttle to defeat.
curl -s -X POST -d 'password=attacker chosen pass phrase' \
     $BASE/password-reset/vulnerable/confirm/$UID64/$TOKEN/
# password updated for dave                        [HTTP 200]

# 3. Log in as dave and read what the account was protecting.
curl -s -c jar.txt -X POST -d 'username=dave&password=attacker chosen pass phrase' \
     $BASE/accounts/login/
# logged in as dave                                [HTTP 200]
curl -s -b jar.txt $BASE/password-reset/vault/
# <h1>Vault</h1><p>dave: recovery codes: FLAG{reset_link_from_last_year_still_worked}</p>

# 4. The same leaked token against the secure confirm view.
curl -s -X POST -d 'password=attacker chosen pass phrase' \
     $BASE/password-reset/secure/confirm/$UID64/$TOKEN/
# invalid or expired reset link                    [HTTP 400]
```

Re-run `python manage.py seed_labs` to restore dave's password and put the lab
back at the starting position.

The mailed reset link goes to the console backend, so step 1's link is printed in
the `docker compose up` log — that is where to look to see the poisoned host in
the `ALLOWED_HOSTS = ["*"]` case.

## Tests

```bash
docker compose run --rm web python manage.py test labs.post_14_password_reset
# Ran 15 tests in 4.746s
# OK
```

`test_a_leaked_year_old_token_still_takes_over_the_account` is the one that
matters. It fails the moment `views_vulnerable.confirm` starts reading either of
the two columns it already writes.

## Isolation

The lab introduces the reset-flow class and nothing else:

- **Password strength is out of scope.** Neither confirm view calls `validate_password()`, so the two halves are identical in that respect and the diff stays about the token. This project runs on Django's genuine default, `AUTH_PASSWORD_VALIDATORS = []` — see [Lab 13](../post_13_weak_passwords/), which owns that class. (Semgrep's audit tier flags both views for it; see [`scans/README.md`](scans/README.md).)
- **The vault is scoped to `request.user`** with no id in the URL, so this is not an IDOR lab (Post 6), and its output is escaped, so it is not an XSS lab (Post 2).
- **Both request views are `@csrf_exempt`**, matching the repo-wide command-line-first convention — CSRF is Lab 08.
- **The vulnerable flow does scope its token to one user.** A token belonging to someone else is refused (`test_the_vulnerable_flow_scopes_the_token_to_its_own_user`). This flow is not careless; it is careless about exactly two things, and saying so keeps the lesson honest.

## Scanning it

The full write-up is in [`scans/README.md`](scans/README.md). The headline:

**Nothing off the shelf can tell these two views apart.** Across 156 curated rules,
372 audit/registry rules and Bandit's entire plugin set, every finding that reaches
either of the two confirm views lands on the vulnerable **and** the secure one — `no-csrf-exempt`
×2 each, `unvalidated-password` ×1 each, `use-none-for-password-default` ×1 each,
`direct-use-of-httpresponse` ×1 each. A rule that fires identically on the bug and
the fix carries no signal about this vulnerability.

That is the "can't distinguish" outcome in the series' decision table, so the lab
ships a custom rule:

```bash
semgrep scan --config rules/password_reset.yaml \
  labs/post_14_password_reset/views_vulnerable.py \
  labs/post_14_password_reset/views_secure.py
# ❯❯❱ rules.thiagoteixeira.django.security.password-reset.reset-token-never-verified
#    labs/post_14_password_reset/views_vulnerable.py
# Ran 1 rule on 2 files: 1 finding.
```

Fires on the vulnerable view, silent on the secure one. Rule tests:

```bash
semgrep --test --config rules/password_reset.yaml rules/password_reset.py
# 1/1: ✓ All tests passed
```
