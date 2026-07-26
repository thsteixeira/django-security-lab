# Captured scan evidence — Lab 02 (XSS)

These are the **real, unedited scanner runs** behind the post's detection
section, committed so you can read exactly what each tool reported without
booting the lab or installing anything. Each file starts with a header giving
the exact command, tool version, and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | ⚠️ scanned, not asserted | `B308` + `B703` on **both** views — it flags the fix as loudly as the bug |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 (`p/django`, `p/python`, `p/owasp-top-ten`) | SAST | ⚠️ scanned, not asserted | **0 findings** on both views — 156 community rules, none covering this pattern |
| [`semgrep-custom-rule.txt`](semgrep-custom-rule.txt) | Semgrep 1.170.0 (`rules/xss.yaml`) | SAST | ✅ asserted (hermetic job) | the custom rule fires on the vulnerable view (line 32) and is **silent** on the secure one |

## The standard tools can't tell this bug from its fix — so we wrote a rule

Lab 01 (SQL injection) asserts in CI that the SAST tools **fire on the
vulnerable view and stay silent on the secure one**. For XSS-via-`mark_safe`
neither standard tool can do that, for two different reasons:

**Bandit flags both views.** `B308`/`B703` are blacklist checks that match the
`mark_safe()` call by name and never look at the argument, so `mark_safe(c.body)`
(the bug) and `mark_safe(nh3.clean(c.body))` (the fix) are indistinguishable to
it. The finding on `views_secure.py` is a false positive against correct code.

**Semgrep's community rules report nothing at all**, on either view — and *not*
because of taint. Semgrep *has* a `mark_safe` rule
([`avoid-mark-safe`](https://github.com/semgrep/semgrep-rules/blob/develop/python/django/security/audit/avoid-mark-safe.yaml)),
but it is tagged `subcategory: audit`, `confidence: LOW`, and the curated packs
(`p/django`, `p/python`, `p/owasp-top-ten`) don't include it — none of the 156
rules that run target `mark_safe`. Run that rule directly and it fires on **both**
views anyway: it excludes only `format_html()` and string literals, not
`nh3.clean()`, so it flags the sanitised fix exactly as Bandit does.

That is exactly the narrow, documented case where a **custom rule** earns its
place ([`rules/xss.yaml`](../../../rules/xss.yaml), with the stem-paired fixture
[`rules/xss.py`](../../../rules/xss.py)). It is deliberately syntactic —
`mark_safe()` on a value that is not a string literal and not an
`nh3.clean()` / `escape()` / `format_html()` call — so it **fires on the
vulnerable view and stays silent on the secure one**, the clean scan-assert the
standard tools couldn't give. `semgrep-custom-rule.txt` is that run; CI enforces
it in a hermetic job (`semgrep --test` on the fixture, then the fire/silent
assert on the two views).

Its one honest limit, documented in the fixture as `todook`: being syntactic, it
cannot see sanitisation done one line earlier through a variable
(`c = nh3.clean(x); mark_safe(c)`). Taint mode would catch that, but it needs a
source it can trace, and an OSS engine does not resolve a stored model field as
one. The lab views call `mark_safe()` inline, where the rule is exact.

Alongside the rule, `tests.py` remains the runnable proof of the vulnerability
itself (exploit succeeds on the vulnerable view, neutralised on the secure one,
legitimate rich text still renders).

## Reproducing them

SAST needs no server:

```bash
# the standard tools (they can't separate bug from fix here)
bandit -r labs/post_02_xss/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_02_xss/

# the custom rule (it can) — fixture check, then the two views
semgrep --test --config rules/ rules/
semgrep scan --config rules/xss.yaml labs/post_02_xss/views_vulnerable.py   # 1 finding
semgrep scan --config rules/xss.yaml labs/post_02_xss/views_secure.py       # 0 findings
```

To exercise the vulnerability itself rather than a scanner's opinion of it, boot
the lab with `docker compose up` and follow the `curl` walkthrough in
[`../README.md`](../README.md) — post the payload, then read it back live on the
vulnerable board and stripped on the secure one.
