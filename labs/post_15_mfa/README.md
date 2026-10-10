# Lab 15 — Multi-Factor Authentication

Companion lab for the blog post
**[Multi-Factor Authentication](https://thiagoteixeira.tech/blog/)** *(link finalised on publication)*.

| | |
|---|---|
| **OWASP** | A07:2025 — Authentication Failures |
| **CWE** | CWE-308 — Use of Single-factor Authentication · CWE-287 — Improper Authentication |
| **ASVS** | 5.0.0 V6.3.4 — no undocumented authentication pathways; controls and authentication strength enforced consistently across them · V6.1.3 — every pathway documented with the strength it must enforce |
| **NIST** | SP 800-63B-4 §2.2 — AAL2: "proof of possession and control of two distinct authentication factors" |
| **Detection** | **Nothing finds it, and no custom rule is possible.** Bandit: 1 finding, a fixture password (it misses the hardcoded TOTP seed beside it). Semgrep curated packs: **0/156**. Audit tier: 9/372, the two dashboards scored **identically**, no rule definition in any pack mentions `otp`/`is_verified`/`login_required`. The detection that works is a **test sweep**. See [`scans/`](scans/) |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The whole vulnerability is one decorator

```python
# views_vulnerable.py
@login_required                  # are you authenticated?
def dashboard(request): ...

# views_secure.py
@otp_required                    # did you present the second factor on THIS session?
def dashboard(request): ...
```

Every line below those two is identical in both files, bar the `# DANGER:` comment
that marks the bug on the vulnerable side (this repo puts one in every vulnerable
view). Diff them — nothing that *runs* differs.

`@login_required` asks a question the password already answered.
`@otp_required` additionally requires `request.user.is_verified()`, which is true
only when `django_otp.login(request, device)` has recorded a verified device on
the session — and that happens in exactly one place, [`views_verify.py`](views_verify.py),
after a code actually checked out.

## erin did everything right

The seeded victim has a **confirmed `TOTPDevice`**. She enrolled when the company
asked her to. Her password is a strong passphrase and `tests.py` asserts four
plausible guesses fail.

That is the point. The flag is not reachable because a user was careless or a
password was weak — those are Labs 11 and 13. It is reachable because an attacker
who already holds her password walks through a door that never asks for anything
else.

The door this repo ships is the shared password-only endpoint at
`/accounts/login/`. In a real project it is the legacy login form, the mobile
token exchange, the SSO callback, or the support tool that logs an agent in as a
customer. MFA rollouts almost never own every route; the front door gets the work
and a side door quietly keeps issuing sessions that were never told MFA exists.

## Run it

```bash
docker compose up --build        # migrates, seeds, serves on 127.0.0.1:8000
```

## Exploit the pair from the command line

```bash
BASE=http://127.0.0.1:8000

# 1. Log in with the PASSWORD ONLY. No code, no device, no second factor.
curl -s -c jar.txt -X POST -d 'username=erin&password=copper meadow transit fifty' \
     $BASE/accounts/login/
# logged in as erin

# 2. The vulnerable dashboard does not care.
curl -s -b jar.txt $BASE/mfa/vulnerable/dashboard/
# <h1>Dashboard</h1><p>erin: payout plan: FLAG{mfa_enforced_at_login_not_at_the_door}</p>

# 3. The secure dashboard, same session, same second.
curl -s -b jar.txt -o /dev/null -w 'HTTP %{http_code} -> %{redirect_url}\n' \
     $BASE/mfa/secure/dashboard/
# HTTP 302 -> http://127.0.0.1:8000/accounts/login/?next=/mfa/secure/dashboard/
```

Now finish the second factor properly. The device key is a fixed lab constant, so
you can generate a live code with nothing but the standard library:

```bash
CODE=$(python -c "
import hmac,hashlib,struct,time
k=bytes.fromhex('3132333435363738393031323334353637383930')
h=hmac.new(k,struct.pack('>Q',int(time.time())//30),hashlib.sha1).digest()
o=h[-1]&15
print('%06d'%((struct.unpack('>I',h[o:o+4])[0]&0x7fffffff)%10**6))
")

curl -s -b jar.txt -c jar.txt -X POST -d "code=$CODE" $BASE/mfa/verify/
# verified

curl -s -b jar.txt $BASE/mfa/secure/dashboard/
# <h1>Dashboard</h1><p>erin: payout plan: FLAG{mfa_enforced_at_login_not_at_the_door}</p>
```

That last pair is the part worth not skipping: the secure view is not merely
refusing people, it serves the resource the moment the second factor is genuinely
present. A control that blocks the attacker *and* the user is not a control.

(The key is a constant here only so this walkthrough works. In production a TOTP
seed is generated per user and never leaves the server — see [`scans/README.md`](scans/README.md)
for what Bandit does and does not notice about it.)

## Tests

```bash
docker compose run --rm web python manage.py test labs.post_15_mfa
# Ran 13 tests in 4.596s
# OK
```

`test_a_password_only_session_reaches_the_flag` is the one that matters. It fails
the moment `views_vulnerable.dashboard` starts requiring verification.

Two groups are worth reading beyond that:

- **`test_sweep_reports_which_urls_a_password_only_session_can_reach`** is the
  detection technique, since no scanner has one. Drive every URL that should sit
  behind the second factor with a password-only session and collect the ones that
  answer 200. In your project the assertion is `assertEqual(reachable, [])`.
- **Three tests pin `django-otp`'s own throttling**, which is library behaviour
  rather than anything about this lab — see below.

## What changed while building this: there is no unthrottled-OTP view

The plan for this lab called for a second vulnerable/secure pair — an OTP verify
endpoint with no rate limit beside one with a throttle — so a reader could watch a
six-digit code get brute-forced. That pair is not here, because you cannot write
it honestly against `django-otp`. `TOTPDevice.verify_token()` throttles itself:

```python
verify_allowed, _ = self.verify_is_allowed()
if not verify_allowed:
    return False
...
if not verified:
    self.throttle_increment(commit=True)
```

The backoff starts at the **first** failed code and doubles — 1, 2, 4, 8, 16
seconds — and the counter lives on the device row, so it survives a restart and
holds across workers, which a hand-rolled cache counter would not. While throttled
even a *correct* code is refused, which is what makes guessing pointless rather
than merely slow (`test_while_throttled_even_the_correct_code_is_refused`).

Turning the throttle off takes a deliberate, documented setting —
`OTP_TOTP_THROTTLE_FACTOR = 0` ("Set to `0` to disable throttling completely") —
and a lab whose bug is "someone set the throttle to zero" teaches configuration
review, not MFA. So this lab has one class, and `tests.py` asserts the library
behaviour instead.

## Isolation

- **Password strength is out of scope** — erin's passphrase is strong on purpose; assume the attacker already has it. That is Lab 13.
- **Guessing rate is out of scope** — django-otp throttles the device itself, as above. Lab 11 owns rate limiting.
- **The verify endpoint is `@csrf_exempt`**, matching the repo-wide command-line-first convention. CSRF is Lab 08.
- **The record is `request.user`-scoped** with no id in the URL, so this is not IDOR (Lab 06), and output is escaped, so it is not XSS (Lab 02).
- **`django_otp` and `OTPMiddleware` are global** (B8) but inert for every other lab: with no device on the session, the middleware records `None` and nothing changes. The full suite is green across all 15 labs.

## Scanning it

The write-up is in [`scans/README.md`](scans/README.md). The short version: the
curated packs return **0 findings from 156 rules**, the audit tier returns 9 and
scores the vulnerable and secure dashboards **identically**, and no rule definition
in any of the five packs mentions `otp`, `is_verified` or `login_required`.

One registry rule does reach this lab's topic: `is-function-without-parentheses`
flags any `is_*` attribute read without a call, so it catches `if user.is_verified:`
— an MFA check that is always true. It fires here only on `is_authenticated`, a
property, because nothing in the lab reads `is_verified` without calling it.

**No custom rule is possible**, which is a different answer from the seven rules in
[`rules/`](../../rules/) that cover eight other labs. Those key on something
present and wrong. Here the defect is
`@login_required` on a view that should have had `@otp_required` — and there is no
syntactic difference between that and the thousands of `@login_required` views
that are perfectly correct. Which views sit behind a second factor is a policy
decision about the data they serve, and a pattern matcher cannot read policy.
