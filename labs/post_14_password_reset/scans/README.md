# Scan evidence — Lab 14 (Password Reset Flows)

Captured 2026-09-13 against the committed lab. Bandit 1.9.4, Semgrep 1.170.0.
Every command below is reproducible from a clone.

| File | Tool | Headline |
|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | **complete miss** — 5 findings, none in a view file |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 | **both tiers can't distinguish** — every finding in the two confirm views lands on the vulnerable *and* the secure one |
| [`semgrep-custom-rule.txt`](semgrep-custom-rule.txt) | Semgrep 1.170.0 + [`rules/password_reset.yaml`](../../../rules/password_reset.yaml) | fires on vulnerable, silent on secure; fixture 1/1 |

This is the first lab in the series where the answer is not "one tier catches it
and the curated pack excludes it." **No rule anywhere catches it.** That changes
what the evidence has to establish: not *which* tool wins, but that the three that
fire are all firing about something else.

## Bandit: a complete miss, and its near-miss is instructive

```bash
bandit -r labs/post_14_password_reset/
```

Five findings, **none of them in a view file**:

| Finding | Location | What it is |
|---|---|---|
| `B105` hardcoded_password_string | `seed.py:40` | dave's seeded passphrase |
| `B105` hardcoded_password_string | `seed.py:43` | **the leaked reset token** |
| `B105` hardcoded_password_string ×2 | `tests.py:45`, `tests.py:306` | passwords the tests set |
| `B106` hardcoded_password_funcarg | `tests.py:172` | `create_user(..., password=...)` in a fixture |

Bandit walks the Python AST for `B`-numbered risky *constructs*. The defect here
is an **absent call** — `check_token()` never appears — and absence has no AST
node. `set_password()` is the right function, used correctly, on the right object;
nothing about it is suspicious in isolation. This is the same blind spot
[Lab 13](../../post_13_weak_passwords/) documents, arriving from the other
direction: there the missing call was `validate_password()`, here it is
`check_token()`.

The `seed.py:43` finding is worth a second look, because it is the closest any
off-the-shelf tool gets:

```
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: '6f1c1e2a-9b7d-4a3f-8c21-0d5e7a9b4c33'
   Location: labs/post_14_password_reset/seed.py:43:15
```

Bandit has correctly identified that this string is a **credential**. That is the
whole thesis of the post — an unverified reset token *is* a password. But the
property it objects to is that the credential is hardcoded in a fixture, which is
a lab artefact and not the bug. A true observation, about the wrong file, for the
wrong reason.

## Semgrep, curated tier: two findings, and they are the same rule twice

```bash
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_14_password_reset/
# Ran 156 rules on 17 files: 2 findings.
```

| Rule | Fires on | Verdict |
|---|---|---|
| `python.django.security.passwords.use-none-for-password-default` | `views_vulnerable.py:88` **and** `views_secure.py:85` | fires on **both** — zero signal |

Both findings are the same rule, on the same line of code, in both halves of the
lab:

```python
new_password = request.POST.get("password", "")
```

The rule's point is that `""` as a `.get()` default can reach `set_password()` and
silently set an empty password. It is a false positive in both views — each guards
with `if not new_password: return 400` two lines later, which Semgrep does not
see — but even taken at face value, **acting on it changes nothing about whether
the token was verified**. A rule that fires identically on the bug and the fix
cannot be used as a scan-assert.

## Semgrep, audit/registry tier: 17 findings, and the pair is perfectly symmetric

```bash
semgrep scan --config r/python.django --config r/python labs/post_14_password_reset/
# Ran 372 rules on 17 files: 17 findings.
```

This is the tier that rescued Lab 08 and Lab 13. Here is everything it found in
the two views under study:

| Rule | `views_vulnerable.py` | `views_secure.py` | Distinguishes? |
|---|---|---|---|
| `no-csrf-exempt` | L43, L76 | L47, L77 | **no** — 2 each |
| `unvalidated-password` | L92 | L89 | **no** — 1 each |
| `use-none-for-password-default` | L88 | L85 | **no** — 1 each |
| `direct-use-of-httpresponse` | L98 | L94 | **no** — 1 each |

Four rules, ten findings across the pair, **perfectly symmetric** — `no-csrf-exempt`
lands twice in each view, the other three once each. The remaining seven are
`direct-use-of-httpresponse` ×2 on `views_vault.py`, `unvalidated-password` on
`seed.py` and ×2 on `tests.py`, and `hardcoded-password-default-argument` ×2 on
`tests.py` — scaffolding and fixtures, not the flow under study.

Read that table as a whole. It is not that the tier is quiet — 372 rules produced
17 findings, which on a real codebase is a working afternoon. It is that **the
signal is identical on both sides of the only difference that matters**. An
analyst triaging this output has no way to conclude that one of these two views
hands over an account and the other does not.

The `unvalidated-password` pair deserves a note, since it fires on the secure view
too and that is *correct*: neither confirm view calls `validate_password()`. That
is a deliberate scope boundary (password strength is Lab 13's class, and this
project runs on `AUTH_PASSWORD_VALIDATORS = []`), which is exactly why it appears
on both halves and carries no information about this lab's vulnerability.

### Demonstrated on the fixture, not just asserted

The two views in the lab differ in several ways at once, so "nothing distinguishes
them" is worth proving somewhere tighter.
[`rules/password_reset.py`](../../../rules/password_reset.py) is that place — a
committed repo file holding **six** `set_password()` call sites: two broken reset
views, three correct ones, and one accepted false negative. All five standard
configs at once:

```bash
semgrep scan --config p/django --config p/python --config p/owasp-top-ten \
             --config r/python.django --config r/python rules/password_reset.py
# Ran 376 rules on 1 file: 6 findings.
```

| Line | Function | Actually broken? | Rule fired |
|---|---|---|---|
| 34 | `vulnerable_confirm` | **yes** | `unvalidated-password` |
| 45 | `secure_confirm` | no | `unvalidated-password` |
| 63 | `secure_confirm_with_early_return` | no | `unvalidated-password` |
| 74 | `VulnerableConfirmView.post` | **yes** | `unvalidated-password` |
| 88 | `change_own_password` | no | `unvalidated-password` |
| 108 | `vulnerable_token_from_post_body` | **yes** | `unvalidated-password` |

Six call sites, six findings, one rule, **zero discrimination**. Row 88 is the
clearest: an authenticated user changing their own password, no token anywhere,
nothing wrong with it — flagged the same as the view that hands over an account.

The reason is structural rather than an oversight. A rule for this class has to
assert that a verification step is **absent from a flow**, and to avoid drowning in
false positives it must first establish that the value reaching `set_password()`
arrived on a reset token rather than from an already-authenticated user. That
second half is interprocedural taint the community engine does not do — the same
wall [Lab 09](../../post_09_path_traversal/) hits from the other side. What is left
is a rule that matches every `set_password()` it can see, which is what the table
above shows.

What *is* tractable is a narrower, syntactic version of the question, which is
what the custom rule below does.

## The custom rule

Per the series' decision table, an audit rule that **can't distinguish** the pair
still warrants a custom rule, cited as the reason. That is this lab exactly, so it
ships [`rules/password_reset.yaml`](../../../rules/password_reset.yaml).

```bash
semgrep scan --config rules/password_reset.yaml \
  labs/post_14_password_reset/views_vulnerable.py \
  labs/post_14_password_reset/views_secure.py
# ❯❯❱ rules.thiagoteixeira.django.security.password-reset.reset-token-never-verified
#    labs/post_14_password_reset/views_vulnerable.py
# Ran 1 rule on 2 files: 1 finding.
```

The rule matches a function that takes a **token-shaped parameter** and reaches
`set_password()` without `check_token()` appearing anywhere in its body. Keying on
the signature is what keeps it off every authenticated "change your password"
view, which legitimately calls `set_password()` with no token in sight — that case
is in the fixture as an `ok:` line.

### The bug in the first draft of the rule, which the fixture caught

The exclusion clause was originally written the obvious way:

```yaml
- pattern-not: |
    def $VIEW(...):
        ...
        $GEN.check_token(...)
        ...
```

`semgrep --test` failed immediately, flagging `secure_confirm` — correct code — as
a finding. The reason is that a bare `$GEN.check_token(...)` line only matches the
call in **statement position**, e.g. `verified = generator.check_token(...)`. The
way nearly everyone actually writes the guard is:

```python
if not default_token_generator.check_token(user, token):
    return HttpResponse("invalid or expired", status=400)
```

There the call is a sub-expression inside an `if` condition, which the pattern
never saw. The fix is the deep-expression operator, `<... $GEN.check_token(...) ...>`,
which matches the call anywhere inside a statement.

Worth recording because of what the failure mode would have been: a rule that
false-positives on the idiomatic fix and stays quiet on the awkward one — flagging
the code that got it right. That is the same failure the `unvalidated-password`
rule ships with today (documented in [Lab 13](../../post_13_weak_passwords/scans/README.md)),
and the only reason it did not ship here is that the fixture asserts the shape.

### Fixture tests

```bash
semgrep --test --config rules/password_reset.yaml rules/password_reset.py
# 1/1: ✓ All tests passed
```

[`rules/password_reset.py`](../../../rules/password_reset.py) covers:

| Case | Expectation |
|---|---|
| hand-rolled confirm, token looked up and not verified | `ruleid` — fires |
| class-based `post(self, request, uidb64, token)` | `ruleid` — fires |
| `if not check_token(...)` guard | `ok` — silent |
| `verified = check_token(...)` then early return | `ok` — silent |
| authenticated change-your-own-password (no token) | `ok` — silent |
| token read from `request.POST` instead of the URL | `todoruleid` — **accepted false negative** |

The last row is the rule's known limit and is marked as such rather than hidden:
the same bug, read from the body, has no parameter to key on. Widening the rule to
any `set_password()` near a variable named `token` would start firing on
legitimate code, and proving the token is request-derived is the taint analysis
that is not available here.

Both commands run in CI (`custom-rules` job), so the rule cannot rot silently.
