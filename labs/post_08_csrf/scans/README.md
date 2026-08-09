# Captured scan evidence — Lab 08 (CSRF)

These are the **real, unedited scanner runs** behind the post's detection
section, committed so you can read exactly what each tool reported without
booting the lab or installing anything. Each file starts with a header giving
the exact command, tool version, and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | ⚠️ scanned, not asserted | nothing on the views — no `@csrf_exempt` check; only `B106` noise on the test password |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 (`p/django`, `p/python`, `p/owasp-top-ten`) | SAST | ⚠️ scanned, not asserted | **0 findings** on both views — the curated packs exclude the `@csrf_exempt` rule |
| [`semgrep-audit-rule.txt`](semgrep-audit-rule.txt) | Semgrep 1.170.0 (`r/python.django…audit.csrf-exempt`) | SAST | ✅ asserted | the **audit-tier** rule fires on the vulnerable view (`@csrf_exempt`), **silent** on the secure one |

## The tool ships the rule — but in the audit tier the default pack skips

Unlike Labs 06 and 07, Lab 08 needs **no custom rule**. Semgrep already has a rule
for `@csrf_exempt`; it just isn't in the packs an analyst runs by default. That is
the whole lesson.

**Bandit** reports nothing on the views — it has no check for `@csrf_exempt`. The
only thing it flags in the module is a `B106` hardcoded password in the *test*
file (`labpass`), noise unrelated to the class.

**Semgrep's curated community packs** (`p/django`, `p/python`, `p/owasp-top-ten`)
report **0 findings on both views**. But the rule *exists* — it lives in the
**`audit` subcategory**, which the curated packs deliberately exclude to keep
signal-to-noise high (`@csrf_exempt` is a legitimate, deliberate choice on
webhook receivers and some APIs, so a tool can't call every use a bug). Run the
audit/registry tier and it appears:

```bash
# curated packs — MISS it (audit rules excluded)
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_08_csrf/

# the audit-tier rule — CATCHES it, and distinguishes the pair
semgrep scan --config r/python.django.security.audit.csrf-exempt labs/post_08_csrf/views_vulnerable.py  # 1 finding (@csrf_exempt)
semgrep scan --config r/python.django.security.audit.csrf-exempt labs/post_08_csrf/views_secure.py      # 0 findings (@csrf_protect)
```

The rule is `python.django.security.audit.csrf-exempt.no-csrf-exempt`. Because it
fires on the vulnerable view and stays **silent** on the `@csrf_protect` secure
view, it gives a clean vulnerable-fires / secure-silent assert on its own — so
writing a custom rule would just duplicate a rule Semgrep already ships (§6.4.1).
CI asserts this rule (registry-fetched, in the non-hermetic SAST job).

The analyst takeaway is **tier awareness**: a security-critical rule can sit in
the audit tier that a default `p/django` scan silently skips. (Contrast Lab 02,
where the audit-tier `avoid-mark-safe` rule fires on *both* views and can't tell
the bug from the fix — *that* forces a custom rule; here the audit rule
distinguishes cleanly.)

## Why no push-button DAST here

CSRF is a listed DAST class — OWASP ZAP's active scan flags state-changing forms
that lack an anti-CSRF token — and that is a reasonable second opinion to capture
against the booted lab. But note the **SameSite caveat**: Django's `csrftoken`
and `sessionid` cookies default to `SameSite=Lax`, so a modern browser will not
attach them to the attacker's cross-site POST in the first place — the browser
may block the forgery *before* Django's token check would. That is defence in
depth, not a lab defect; the lab's server-side lesson (`@csrf_protect` rejects the
tokenless POST with 403) stands regardless, and `tests.py` proves it with
`Client(enforce_csrf_checks=True)`.
