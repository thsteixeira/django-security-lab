# Scan evidence — Lab 15 (Multi-Factor Authentication)

Captured 2026-09-13; re-captured 2026-10-10 after the lab gained its policy rule
(`rules/mfa.yaml` and its fixture): the same findings, over more files. Bandit
1.9.4, Semgrep 1.170.0.
Every command below is reproducible from a clone.

| File | Tool | Headline |
|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | **1 finding** — a fixture password; it misses the hardcoded TOTP secret beside it |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 | curated packs **0/180**; audit tier 9/372, none about authorization |
| [`semgrep-custom-rule.txt`](semgrep-custom-rule.txt) | Semgrep 1.170.0 | the lab's **policy rule**: fires on the vulnerable dashboard, silent on the secure one; fixture 2/2 |

No registry rule tells the bug from the fix, and none can on its own: the two
dashboards are identical below `@login_required` / `@otp_required`, and which
views need a second factor is a decision about their data. So this lab ships a
**policy rule** — told that decision — and keeps it in its own `rules/`, beside
the models it names, rather than in the repo-wide `rules/`.

## Bandit: one finding, and it is the wrong constant

```bash
bandit -r labs/post_15_mfa/
# >> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'copper meadow transit fifty'
#    Location: labs/post_15_mfa/seed.py:33:18
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
finds credentials by asking what they are *called* misses every credential whose
name is not on its list — "key" is not on B105's, "secret" is. Name the same
constant `TOTP_SECRET` and Bandit reports it.

## Semgrep, curated tier: silence

```bash
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_15_mfa/
# Ran 180 rules on 18 files: 0 findings.
```

Zero. Not a false positive to triage, not a near miss — the curated packs have
nothing to say about a Django project with MFA wired into it. (180 = 151 Python
+ 5 multilang rules, plus 24 YAML rules that apply only because the lab now ships
`rules/mfa.yaml`.)

## Semgrep, audit/registry tier: 9 findings, none about the gate

```bash
semgrep scan --config r/python.django --config r/python labs/post_15_mfa/
# Ran 372 rules on 18 files: 9 findings.
```

| Rule | Where | Relevant? |
|---|---|---|
| `direct-use-of-httpresponse` | `views_vulnerable.py` L38, L44 · `views_secure.py` L35, L41 | no — **2 on each**: both build their HTML with `HttpResponse` instead of a template, the labs' convention (Lab 02's class) |
| `no-csrf-exempt` | `views_verify.py` L37 | no — global CSRF is off by design (Lab 08's class) |
| `unvalidated-password` | `seed.py` L45 · `tests.py` L47 | no — fixtures calling `set_password()` (Lab 13's class) |
| `is-function-without-parentheses` | `views_verify.py` L40 · `tests.py` L98 | no — and **wrong**, see below |

The two dashboards differ by exactly one decorator, and the tier scores them
**identically**: two `direct-use-of-httpresponse` each. Nothing separates them.

No rule in either tier is written about a second factor. Grepping the rule
definitions themselves — all five packs, fetched from the registry on 2026-10-10 —
for `is_verified` or `login_required` (case-sensitive, as Python identifiers are)
or `otp` in any case returns **zero matches**:

```bash
for c in p/django p/python p/owasp-top-ten r/python.django r/python; do
  curl -sL "https://semgrep.dev/c/$c" | grep -cE 'is_verified|login_required|[Oo][Tt][Pp]'
done
# 0
# 0
# 0
# 0
# 0
```

Make the whole pattern case-insensitive and `p/owasp-top-ten` returns 4 lines,
all from one PHP rule's `$IS_VERIFIED` metavariable (`CURLOPT_SSL_VERIFYPEER`),
which is about TLS, not users. The scan's own JSON cannot answer this question: it
holds only the rules that fired, and without a login it replaces every matched
source line with `"requires login"`.

### The `is_*` rule fires on the fix — and would catch the live trap

`is-function-without-parentheses` fires twice, on `is_authenticated` read as an
attribute:

```python
if not request.user.is_authenticated:                       # views_verify.py:40
self.assertTrue(resp.wsgi_request.user.is_authenticated)    # tests.py:98
```

The rule exists for a real historical bug — `is_authenticated` used to be a
method, and `if user.is_authenticated:` on a bound method is always truthy. But it
stopped being a method in **Django 1.10** (2016) and is a property now, so both
lines above are the correct modern spelling and the rule is firing on the fix.

That is worth dwelling on, because the *same trap is live for this lab's topic*.
`is_verified` **is** a method:

```python
if user.is_verified:      # always truthy — the callable itself. MFA checks nothing.
if user.is_verified():    # correct
```

(`OTPMiddleware` installs it as `functools.partial(is_verified, user)`, not a bound
method, but the effect is the same.) The registry rule already covers it: it
matches any `is_*` attribute read without a call (`metavariable-regex: is_.*`),
and pointed at `if user.is_verified:` it fires. It is silent on that here only
because this lab never writes the bug.

## The custom rule: the policy, written down

The defect is `@login_required` on a view that **should** have carried
`@otp_required`. There is no syntactic difference between that and the thousands
of `@login_required` views that are entirely correct — a marketing dashboard, a
profile page, a support form. Which views sit behind a second factor is a
**policy decision about the data they serve**. A rule that flagged every
`@login_required` view would fire on all of them and mean nothing.

Semgrep cannot guess that policy, but it can enforce one it is given.
[`rules/mfa.yaml`](../rules/mfa.yaml) carries two rules:

- **`sensitive-model-behind-password-only-gate`** (ERROR). The policy is one
  regex: the models this project puts behind MFA (`^(SensitiveRecord)$`). The rule
  flags a function decorated `@login_required` — bare or called with arguments —
  and not `@otp_required`, that reads one of them through `.objects`,
  `get_object_or_404()` or `get_list_or_404()`.
- **`session-minted-without-second-factor`** (INFO). An inventory, not a verdict:
  it lists every `django.contrib.auth.login()` call, the session-minting paths
  the post says to find. `django_otp.login()` is a different function and is not
  listed.

```bash
semgrep scan --config labs/post_15_mfa/rules/mfa.yaml \
    labs/post_15_mfa/views_vulnerable.py labs/post_15_mfa/views_secure.py \
    labs/_common/views.py
# Ran 2 rules on 3 files: 2 findings.
semgrep --test --config labs/post_15_mfa/rules/ labs/post_15_mfa/rules/
# 2/2: ✓ All tests passed
```

The two findings: the gate rule on `views_vulnerable.py:36`, and the inventory
rule on `labs/_common/views.py:28`. The gate rule is **silent on the secure
dashboard** — the split no registry tier gives. The inventory rule finds the shared
password-only endpoint that is this lab's side door. Both commands run in CI.

The fixture ([`rules/mfa.py`](../rules/mfa.py)) also records what the rules
cannot see, each marked `todoruleid`: a sensitive read inside a helper the view
calls, a class-based view (`LoginRequiredMixin` has no decorator to key on), a
view wrapped in `urls.py`, and a hand-rolled session that writes `_auth_user_id`
without calling `login()`. And the model list is kept by hand: a sensitive model
added next quarter is not covered until someone adds it to the regex.

It lives in the lab rather than in the repo-wide `rules/` because it is not a
general Django rule: the regex names this lab's models. Another project copies it
and edits the list.

## And a test sweep

The rule needs a model list; the test needs a URL list. A sweep — `test_sweep_reports_which_urls_a_password_only_session_can_reach`:

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
it — the same weakness as the rule's model list. The two fail differently, which is
why the lab keeps both: the rule reads code without running it, the sweep exercises
behaviour without reading code. A sensitive read the rule cannot see — in a helper,
in a class-based view — still answers 200 to the sweep, if its URL is on the list.

## A library behaviour this lab pins

Three tests assert `django-otp`'s own throttling rather than anything about the
vulnerability. `TOTPDevice.verify_token()` calls `verify_is_allowed()` before it
checks anything and `throttle_increment()` on failure, so the backoff starts at the
**first** wrong code and doubles — 1, 2, 4, 8, 16 seconds — with the counter stored
on the device row, surviving restarts and shared across workers.

That is why this lab has no "unthrottled OTP" view to brute-force: turning the
throttle off takes a deliberate, documented setting (`OTP_TOTP_THROTTLE_FACTOR = 0`),
and a lab whose bug is "someone set the throttle to zero" teaches configuration
review, not MFA. The tests pin the behaviour so a future release that weakens it turns
this repo red instead of quietly making the post wrong — the same reason Lab 13
asserts that Django's four default validators accept `Password123!`.
