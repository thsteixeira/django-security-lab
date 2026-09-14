# Scan evidence — Lab 15 (Multi-Factor Authentication)

Captured 2026-09-13 against the committed lab. Bandit 1.9.4, Semgrep 1.170.0.
Every command below is reproducible from a clone.

| File | Tool | Headline |
|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | **1 finding** — a fixture password; it misses the hardcoded TOTP secret beside it |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 | curated packs **0/156**; audit tier 9/372, none about authorization |

This lab ships **no custom rule**. Nor do Labs 11, 12 and 13 — but those three are
silent for ordinary reasons (an absent control, a setting, an audit-tier rule that
already fires). Here the reason is different in kind: the thing that is wrong
cannot be expressed as a pattern at all. That conclusion is the finding.

## Bandit: one finding, and it is the wrong constant

```bash
bandit -r labs/post_15_mfa/
# Total issues (by severity): Low: 1
```

The single finding is `B105 hardcoded_password_string` on `seed.py:33`,
`VICTIM_PASSWORD`. It is a lab fixture, and unavoidable in a lab that has to name
the password it hands the attacker.

Now look at what is **not** flagged, four lines below it:

```python
TOTP_KEY = "3132333435363738393031323334353637383930"
```

That is the second factor. It is a shared secret which, if it leaks, lets anyone
generate erin's codes forever — strictly worse than the password, because users
rotate passwords and nobody rotates a TOTP seed. Bandit reports the password and
walks past the seed.

The mechanism is not subtle: `B105` matches on the **variable name**, against a
list of password-ish words. `VICTIM_PASSWORD` contains "password". `TOTP_KEY` does
not contain anything on the list, so the string is just a string. A tool that
finds credentials by asking what they are *called* will miss every credential
named after what it actually is.

## Semgrep, curated tier: silence

```bash
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_15_mfa/
# Ran 156 rules on 15 files: 0 findings.
```

Zero. Not a false positive to triage, not a near miss — the curated packs have
nothing to say about a Django project with MFA wired into it.

## Semgrep, audit/registry tier: 9 findings, none about the gate

```bash
semgrep scan --config r/python.django --config r/python labs/post_15_mfa/
# Ran 372 rules on 15 files: 9 findings.
```

| Rule | Where | Relevant? |
|---|---|---|
| `direct-use-of-httpresponse` | `views_vulnerable.py` L38, L44 · `views_secure.py` L31, L37 | no — **2 on each**, the labs' plain-text convention (Lab 02's class) |
| `no-csrf-exempt` | `views_verify.py` L37 | no — global CSRF is off by design (Lab 08's class) |
| `unvalidated-password` | `seed.py` L45 · `tests.py` L47 | no — fixtures calling `set_password()` (Lab 13's class) |
| `is-function-without-parentheses` | `views_verify.py` L40 · `tests.py` L98 | no — and **wrong**, see below |

The two dashboards differ by exactly one decorator, and the tier scores them
**identically**: two `direct-use-of-httpresponse` each. Nothing separates them.

Searching the full JSON output of all 372 rules for `otp`, `is_verified` or
`login_required` returns **zero matches**. The tooling has no concept of a second
factor to have an opinion about.

### The one auth-adjacent rule that fires is a false positive

`is-function-without-parentheses` fires twice — `views_verify.py:40` and
`tests.py:98` — both times on the same construct:

```python
if not request.user.is_authenticated:
```

The rule exists for a real historical bug — `is_authenticated` used to be a
method, and `if user.is_authenticated:` on a bound method is always truthy. But it
stopped being a method in **Django 1.10** (2016) and is a property now, so the
line above is the correct modern spelling and the rule is firing on the fix.

That is worth dwelling on, because the *same trap is live for this lab's topic*.
`is_verified` **is** a method:

```python
if user.is_verified:      # always truthy — a bound method. MFA checks nothing.
if user.is_verified():    # correct
```

A rule for that would be valuable, and the registry ships one aimed at the
decade-old version of the problem while the current one goes unmatched.

## Why there is no custom rule

Seven rules live in `rules/`, covering eight labs (Labs 07 and 10 share one).
This lab adds none, and the reason is a category difference rather than effort.

Those seven all key on something **present and wrong**: `mark_safe()` on
a non-literal, `fields="__all__"` in a `Meta`, an `os.path.join` reaching `open`,
a token parameter reaching `set_password()` with no `check_token()`. Each is a
syntactic fact about code that exists.

Here the defect is `@login_required` on a view that **should** have carried
`@otp_required`. There is no syntactic difference between that and the thousands
of `@login_required` views that are entirely correct — a marketing dashboard, a
profile page, a support form. Which views sit behind a second factor is a
**policy decision about the data they serve**, and a pattern matcher cannot read
policy. A rule that flagged every `@login_required` view would fire on all of them
and mean nothing, which is the definition of noise.

This is the same floor Lab 11 (brute force) and Lab 12 (session fixation) hit,
from a third direction: there the defect was an absent control and a
wrongly-keyed one; here it is a *correct* control applied to the wrong question.

## What detects it instead

A test, and specifically a sweep — `test_sweep_reports_which_urls_a_password_only_session_can_reach`:

```python
protected_area = [VULN, SECURE]
attacker = self.password_only_session()
reachable = [url for url in protected_area if attacker.get(url).status_code == 200]
self.assertEqual(reachable, [VULN])
```

Drive every URL that is supposed to sit behind the second factor with a session
that only ever presented a password, and collect the ones that answer 200. In your
project the assertion is `assertEqual(reachable, [])`. Here it is deliberately
non-empty, so the sweep is shown catching the lab's own bug rather than asserted
in the abstract.

It is worth being clear about what that costs: the list of protected URLs is
maintained by hand, so a view added next quarter is not covered until someone adds
it. That is a real weakness, and it is still better than the alternative, because
the alternative is nothing.

## A library behaviour this lab pins

Three tests assert `django-otp`'s own throttling rather than anything about the
vulnerability. `TOTPDevice.verify_token()` calls `verify_is_allowed()` before it
checks anything and `throttle_increment()` on failure, so the backoff starts at the
**first** wrong code and doubles — 1, 2, 4, 8, 16 seconds — with the counter stored
on the device row, surviving restarts and shared across workers.

That is why this lab has no "unthrottled OTP" view to brute-force: writing one
would mean reaching past the library's own API to the raw TOTP verifier, which is a
straw man. The tests pin the behaviour so a future release that weakens it turns
this repo red instead of quietly making the post wrong — the same reason Lab 13
asserts that Django's four default validators accept `Password123!`.
