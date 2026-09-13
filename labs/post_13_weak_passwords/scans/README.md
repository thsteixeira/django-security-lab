# Scan evidence — Lab 13 (Weak Passwords & Validators)

Captured 2026-09-13 against the committed lab. Bandit 1.9.4, Semgrep 1.170.0.
Every command below is reproducible from a clone.

| File | Tool | Headline |
|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | **complete miss** — 4 findings, none on the vulnerability |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 | curated packs **miss**; the **audit tier catches it** — with one false positive and a broken autofix |

## Bandit: a complete miss, and its loudest finding is on the fix

```bash
bandit -r labs/post_13_weak_passwords/
```

Four findings, **none** of them the unvalidated `set_password()`:

| Finding | Location | What it is |
|---|---|---|
| `B105` hardcoded_password_string ×3 | `seed.py:30`, `seed.py:34`, `tests.py:123` | the lab's own fixtures. Unavoidable in a lab that must name the passwords it demonstrates |
| `B310` blacklist (urlopen schemes) | `validators.py:92` | on the **secure** validator. The URL is a module-level `https://` constant interpolated with a 5-hex-character prefix, so no `file:` or custom scheme is reachable — but Bandit does not do the constant propagation needed to see that |

Bandit walks the Python AST looking for `B`-numbered risky *constructs*. The defect
here is not a construct — it is the **absence of a call** next to an entirely
correct one. `set_password()` is the right function, used correctly; nothing about
its AST node is suspicious. Bandit has no model of Django's password-validation
subsystem at all, so there is nothing for it to notice.

**One finding was real and was fixed.** The first capture also carried
`B324:hashlib — Use of weak SHA1 hash for security` (High/High) on
`PwnedPasswordValidator`. SHA-1 is not a choice there — it is the wire format the
HIBP range API defines, used as a lookup key into a public corpus, not to protect
anything. The correct answer is to *say so in the code* rather than suppress the
check, so `validators.py` now calls
`hashlib.sha1(..., usedforsecurity=False)`, which also keeps the call working on
FIPS-restricted builds. B324 no longer fires. No `# nosec` was used anywhere.

## Semgrep, curated tier: three findings, none of them the bug

```bash
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_13_weak_passwords/
# Ran 156 rules on 18 files: 3 findings.
```

| Rule | Fires on | Verdict |
|---|---|---|
| `python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1` | `validators.py` (the **secure** code) | false positive — see the autofix warning below |
| `python.django.security.passwords.use-none-for-password-default` | `views_vulnerable.py` **and** `views_secure.py` | fires on **both** — cannot distinguish |

Note the shape of that second result. A rule that fires identically on the
vulnerable and the secure view carries **zero** signal about this vulnerability:
acting on it changes nothing about whether the password is validated. (It is also
a false positive on its own terms — both views guard with
`if not username or not password: return 400`, so an empty password can never
reach `set_password()`. Semgrep does not see the guard.)

**The SHA-1 autofix would break the control.** Semgrep offers
`hashlib.sha256(...)` as an autofix on `validators.py`. Applying it would send a
SHA-256 prefix to an API that indexes by SHA-1, so every lookup would miss, every
password would come back "not breached", and the validator would silently pass
everything while still appearing to run.

## Semgrep, audit tier: catches it — and misfires on the idiomatic fix

```bash
semgrep scan --config r/python.django --config r/python labs/post_13_weak_passwords/
# Ran 372 rules on 18 files: 18 findings.
```

The lab ships **three** registration views on purpose, and the rule scores them
differently:

| View | What it does | Rule verdict |
|---|---|---|
| [`views_vulnerable.py:37`](../views_vulnerable.py) | `set_password()`, no validation | **fires** — true positive |
| [`views_secure.py`](../views_secure.py) | `validate_password()` in a `try/except`, same scope | **silent** — true negative |
| [`views_form.py:73`](../views_form.py) | validation in a `Form.clean_password()`, write in the view | **fires** — **false positive** |

It also fires on `seed.py:43` and `tests.py:43`, which are fixtures.

The first two rows are the ones that decide the custom-rule question: the rule
fires on the bug and not on the inline fix, so per §6.4.1 this lab ships **no
custom rule**. The finding is *"the curated packs do not include it — run the
audit tier"* — the same shape as Lab 08 (CSRF).

The third row is the caveat that matters in practice, and it is covered below.

### Why the curated pack misses it — verified, not assumed

From the rule's own published definition
(<https://semgrep.dev/r/python.django.security.audit.unvalidated-password.unvalidated-password>):

```yaml
metadata:
  subcategory: [audit]
  confidence: LOW
  likelihood: LOW
  impact: MEDIUM
  cwe: ['CWE-521: Weak Password Requirements']
```

`subcategory: audit` is the mechanism. The curated `p/*` packs deliberately
exclude audit-subcategory rules, because an audit rule is a *review prompt* rather
than a high-confidence defect — which `confidence: LOW` says outright. So the rule
exists, has existed for years, and simply never runs in the default Django pack.
This is the same reason Lab 08's `no-csrf-exempt` and Lab 02's `avoid-mark-safe`
are invisible to `p/django`.

### Why it can distinguish — the rule's actual pattern

The rule is `$MODEL.set_password($X)` fenced by four `pattern-not-inside` clauses,
one of which is:

```yaml
- pattern-not-inside: |
    try:
      ...
      django.contrib.auth.password_validation.validate_password(...)
      ...
    except $EX as $E:
      ...
    ...
```

`views_secure.py` writes exactly that shape, which is why it is excluded.

Note what those clauses have in common: every one of them looks for
`validate_password(...)` **in the same lexical scope** as the `set_password()`
call. That is the entire extent of the rule's reasoning — it does not follow
function calls, and it has no notion of a form having already validated the data.

**Confirmed causally, not by correlation.** A copy of `views_secure.py` with
*only* the `try/except validate_password` guard removed — every other byte
identical — was scanned on its own:

```bash
semgrep scan --config r/python.django <mutant-dir>
# ❯❱ python.django.security.audit.unvalidated-password
#    42┆ user.set_password(password)
```

The rule fires on the same `set_password()` line the moment the guard is gone. It
keys on the call, not on the filename or anything incidental.

### ⚠️ The rule's published autofix is broken — do not apply it

Semgrep offers this fix:

```python
if django.contrib.auth.password_validation.validate_password($X, user=$MODEL):
    $MODEL.set_password($X)
```

`validate_password()` **returns `None` on success and raises `ValidationError` on
failure.** It never returns a truthy value, so the branch is never taken and
`set_password()` never runs. Verified inside the lab container:

```
validate_password returns: None
  -> branch taken?            False
  -> u.password after autofix: ''
  -> u.has_usable_password(): True
```

Applying the autofix does not harden registration — it silently stops setting
passwords at all, and because `has_usable_password()` only looks for the `!`
unusable-password prefix, the resulting accounts are not even flagged as
password-less. They are simply accounts nobody can ever log into. The correct
shape is the `try`/`except ValidationError` in
[`views_secure.py`](../views_secure.py).

### The false positive: validation one scope away

[`views_form.py`](../views_form.py) is the shape most real Django applications
use, and the one this lab recommends over hand-rolling: a `Form` validates in
`clean_password()`, the view writes only after `is_valid()` has passed. Django's
own `SetPasswordForm` and `BaseUserCreationForm` are built this way.

The rule flags it anyway:

```
labs/post_13_weak_passwords/views_form.py:73   user.set_password(form.cleaned_data["password"])
```

The guard is real, it runs first, and a failed validation means `register()` never
reaches that line — but the `validate_password()` call is in
`RegistrationForm.clean_password()`, one function call and one scope away, and the
rule's `pattern-not-inside` fences only see the function they are in.

This is worth internalising before running the rule across a real codebase: **the
more idiomatic your Django is, the more likely this rule is to be wrong about
it.** A `confidence: LOW` audit rule is a list of places to go and read, not a
list of defects — which is precisely why it is not in the curated pack.

## The rest of the audit-tier noise (18 findings total)

| Rule | Where | Why it is not this lab's lesson |
|---|---|---|
| `no-csrf-exempt` ×3 | all three registration views | the project runs with global CSRF off by design; that is Lab 08 |
| `direct-use-of-httpresponse` ×7 | all four view modules | the labs answer in plain text for `curl`; output is escaped. XSS is Lab 02 |
| `use-none-for-password-default` | both views | see above — fires on both, guarded in both |
| `dynamic-urllib-use-detected` | `validators.py` | the Semgrep counterpart of Bandit's `B310`, same false positive |
| `insecure-hash-algorithm-sha1` | `validators.py` | the HIBP wire format, already answered with `usedforsecurity=False` |
| `unvalidated-password` | `seed.py`, `tests.py` | fixtures — the rule matches any `$MODEL.set_password($X)`, including the ones that plant the lab's own data |

Two of those fixture hits are worth keeping in mind when you run this rule on a
real codebase: it will flag your test factories and your seed scripts too. That
is the cost of a `confidence: LOW` rule, and it is why the rule lives in the audit
tier rather than the curated pack.
