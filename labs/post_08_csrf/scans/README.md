# Captured scan evidence — Lab 08 (CSRF)

These are the **real, unedited scanner runs** behind the post's detection
section, committed so you can read exactly what each tool reported without
booting the lab or installing anything. Each file starts with a header giving
the exact command, tool version, and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | ⚠️ scanned, not asserted | nothing on the views — no `@csrf_exempt` check; only `B106` noise on the test password |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 (`p/django`, `p/python`, `p/owasp-top-ten`) | SAST | ⚠️ scanned, not asserted | **0 findings** on both views — the curated packs exclude the `@csrf_exempt` rule |
| [`samesite-browser.txt`](samesite-browser.txt) | Chrome 155 headless, against a stand-in view | browser | ❌ not in CI | the forged POST arrives **without** the `SameSite=Lax` session from `file://` and `localhost` (cross-site), **with** it from `127.0.0.1` on another port (same site) |
| [`semgrep-audit-rule.txt`](semgrep-audit-rule.txt) | Semgrep 1.170.0 (`r/python.django…audit.csrf-exempt`; + `p/security-audit`) | SAST | ✅ asserted (the named rule) | the **audit-tier** rule fires on the vulnerable view (`@csrf_exempt`), **silent** on the secure one; `p/security-audit` gives the same pair |

## The tool ships the rule — but in the audit tier the default pack skips

Unlike Labs 06 and 07, Lab 08 needs **no custom rule**. Semgrep already has a rule
for `@csrf_exempt`; it just isn't in the packs an analyst runs by default. That is
the whole lesson.

**Bandit** reports nothing on the views — it has no check for `@csrf_exempt`. The
only thing it flags in the module is a `B106` hardcoded password in the *test*
file (`labpass`), noise unrelated to the class.

**Semgrep's curated community packs** (`p/django`, `p/python`, `p/owasp-top-ten`)
report **0 findings on both views**. But the rule *exists* — it lives among
Semgrep's `security/audit` rules (its metadata says `subcategory: vuln`,
`confidence: LOW`; `@csrf_exempt` is a legitimate, deliberate choice on webhook
receivers and some APIs, so a tool can't call every use a bug), and none of the
three packs includes it. Run it by name, or through the
`p/security-audit` pack (79 rules on each view; the same one finding on the
vulnerable view, none on the secure one), and it appears:

```bash
# curated packs — MISS it (audit rules excluded)
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_08_csrf/

# the audit-tier rule — CATCHES it, and distinguishes the pair
semgrep scan --config r/python.django.security.audit.csrf-exempt labs/post_08_csrf/views_vulnerable.py  # 1 finding (@csrf_exempt)
semgrep scan --config r/python.django.security.audit.csrf-exempt labs/post_08_csrf/views_secure.py      # 0 findings (@csrf_protect)
```

The rule is `python.django.security.audit.csrf-exempt.no-csrf-exempt`. It matches
the decorator only on a function: `@method_decorator(csrf_exempt, ...)` on a
class-based view and `csrf_exempt(view)` in a `urls.py` pass it silently
(Semgrep 1.170.0, Oct 23, 2026), so a `grep` for `csrf_exempt` stays the first
check. Because it
fires on the vulnerable view and stays **silent** on the `@csrf_protect` secure
view, it gives a clean vulnerable-fires / secure-silent assert on its own — so
writing a custom rule would just duplicate a rule Semgrep already ships (§6.4.1).
CI asserts this rule (registry-fetched, in the non-hermetic SAST job).

The analyst takeaway is **tier awareness**: a security-critical rule can sit in
the audit tier that a default `p/django` scan silently skips. (Contrast Lab 02,
where the audit-tier `avoid-mark-safe` rule fires on *both* views and can't tell
the bug from the fix — *that* forces a custom rule; here the audit rule
distinguishes cleanly.)

## Why there is no captured DAST run here

CSRF is a listed DAST class, and OWASP ZAP has a passive rule for it — **Absence
of Anti-CSRF Tokens** flags a form carrying no token field. This directory ships
**no captured ZAP run**, for two honest reasons:

1. **The form is auth-gated.** The transfer view is behind `@login_required`, so
   an unauthenticated ZAP spider/baseline is redirected to login and never
   reaches it. A faithful run needs an *authenticated* ZAP context (a login
   script + session handling) — more setup than this finding earns, and beyond
   what a reader can reproduce with one command.
2. **That rule would not fire here.** Both views render the same form, and it
   carries a `csrfmiddlewaretoken` field (`_transfer.py` calls `get_token()`);
   the vulnerable view simply never checks it. A passive scan sees a token and
   stays quiet. What proves the gap is a request sent *without* the token, which
   is what `tests.py` does. (Django's `SameSite=Lax` cookies also stop the
   cross-site version in a browser; see [`samesite-browser.txt`](samesite-browser.txt).)

So DAST here is **deferred with a reason** (as in the stored-XSS and SSTI labs),
not captured. The server-side lesson (`@csrf_protect` rejects the tokenless POST
with `403`) stands regardless, and `tests.py` proves it deterministically with
`Client(enforce_csrf_checks=True)`.
