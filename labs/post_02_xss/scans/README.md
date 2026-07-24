# Captured scan evidence — Lab 02 (XSS)

These are the **real, unedited scanner runs** behind the post's detection
section, committed so you can read exactly what each tool reported without
booting the lab or installing anything. Each file starts with a header giving
the exact command, tool version, and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | ⚠️ scanned, not asserted | `B308` + `B703` on **both** views — it flags the fix as loudly as the bug |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 (`p/django`, `p/python`, `p/owasp-top-ten`) | SAST | ⚠️ scanned, not asserted | **0 findings** on both views — 156 community rules, none covering this pattern |

## Why this lab has no scan-assert in CI

Lab 01 (SQL injection) asserts in CI that the SAST tools **fire on the
vulnerable view and stay silent on the secure one**. That assertion is a lie
here, and pretending otherwise would be the easiest way to make this repo
untrustworthy.

**Bandit flags both views.** `B308`/`B703` match the `mark_safe()` call itself.
It does not look at the argument, so `mark_safe(c.body)` (the bug) and
`mark_safe(nh3.clean(c.body))` (the recommended fix) are indistinguishable to
it. The finding on `views_secure.py` is a false positive against code that is
already correct.

**Semgrep's community rules report nothing at all**, on either view. Its taint
analysis needs a source it recognises; a value read off a model instance is not
one, so there is no traceable path from source to sink and nothing to report.

So the two tools fail in opposite directions on the same code — one is too
coarse to tell the bug from the fix, the other does not see it. **The gate for
this lab is `tests.py`**, which asserts the exploit succeeds on the vulnerable
view, is neutralised on the secure one, and that legitimate rich text still
renders. That is the universal gate every lab carries, and here it is the only
honest one.

This is the empirical result of the detection pass, not a prediction — and a
lab whose class the standard tools do not cleanly catch is an expected outcome,
not a defect.

## Reproducing them

SAST needs no server:

```bash
bandit -r labs/post_02_xss/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_02_xss/
```

To exercise the vulnerability itself rather than a scanner's opinion of it, boot
the lab with `docker compose up` and follow the `curl` walkthrough in
[`../README.md`](../README.md) — post the payload, then read it back live on the
vulnerable board and stripped on the secure one.
