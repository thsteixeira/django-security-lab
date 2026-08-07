# Lab 06 — Broken Access Control / IDOR

Companion lab for the blog post
**[Broken Access Control & IDOR: When Logging In Is Not the Same as Being Allowed](https://thiagoteixeira.tech/blog/broken-access-control-and-idor-when-logging-in-is-not-the-same-as-being-allowed/)**.

| | |
|---|---|
| **OWASP** | A01:2021 — Broken Access Control |
| **CWE** | CWE-639 — Authorization Bypass Through User-Controlled Key |
| **ASVS** | V4.2.1 — protect data/APIs against IDOR |
| **Detection** | SAST — the standard tools **miss** this class; a **custom rule** ([`rules/idor.yaml`](../../rules/idor.yaml)) catches it, asserted in CI (see Scanning it) |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The two views

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | `get_object_or_404(Note, pk=pk)` — behind `@login_required`, but the lookup is scoped to the **whole table** |
| Secure | [`views_secure.py`](views_secure.py) | `get_object_or_404(Note, pk=pk, owner=request.user)` — the lookup is scoped to the **requester** |

Both views are the same "view a note" feature, and both require you to be logged
in. The difference is that authentication is not authorisation: the vulnerable
view checks *who you are* but never *whether this note is yours*, so any
logged-in user can read any note by walking the sequential primary keys. The fix
adds one thing — `owner=request.user` — which turns the lookup into
`Note.objects.filter(pk=pk, owner=request.user)`: another user's note simply is
not in the result set, so Django raises a **404** indistinguishable from a note
that never existed. The attacker learns nothing.

The flag lives in the **body of a note owned by `bob`**. Capturing it as `alice`
*is* the vulnerability: you are reading a record behind an ownership boundary you
were never granted.

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
```

The seed prints the note ids on startup — check them with `docker compose logs web | grep idor`:

```
idor: seeded cast + notes — alice's note pk=1, bob's flagged note pk=2
```

On a fresh stack **Bob's flagged note is `pk=2`** and Alice's own note is `pk=1`.

Everything below is `curl` against that stack — no browser needed. Run the `curl`
commands in a POSIX shell (Linux, macOS, WSL, or **Git Bash** on Windows). On
Windows PowerShell, `curl` is an alias for `Invoke-WebRequest` — use `curl.exe`
instead, or just switch to Git Bash.

## Test the pair from the command line

**1. Log in as `alice` (the attacker).** Session auth: save the cookie to a jar
and reuse it. The cast password is `labpass`.

```bash
curl -s -c jar.txt -d 'username=alice&password=labpass' http://127.0.0.1:8000/accounts/login/
# logged in as alice
```

**2. Exploit it.** Alice reads **Bob's** note (`pk=2`) on the vulnerable view —
authenticated, but not authorised — and the flag comes back:

```bash
curl -s -b jar.txt http://127.0.0.1:8000/idor/vulnerable/2/ | grep -o 'FLAG{[^}]*}'
# FLAG{idor_via_unscoped_object_lookup}
```

**3. The same request against the secure view.** The lookup is scoped to Alice,
so Bob's note is not in her queryset and the response is a 404 that leaks nothing:

```bash
curl -s -b jar.txt -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/idor/secure/2/
# 404
```

**4. The fix does not break legitimate access.** Alice still reads **her own**
note (`pk=1`) on the secure view:

```bash
curl -s -b jar.txt http://127.0.0.1:8000/idor/secure/1/ | grep -o 'milk, eggs, bread'
# milk, eggs, bread
```

**5. Authentication is still required.** Without the cookie, the vulnerable view
redirects to the login page rather than serving anything — the bug is *missing
authorisation*, not *missing authentication*:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/idor/vulnerable/2/
# 302   (redirect to /accounts/login/)
```

Or prove all of it in one command (from the repo root):

```bash
docker compose run --rm web python manage.py test labs.post_06_idor
```

> **Why `curl`, not a browser.** The bug is server-side authorisation: the same
> PK returns another user's record on one view and a 404 on the other, which the
> status code and `grep` show plainly. Output is HTML-escaped, so a note body
> cannot turn this into an XSS demo — the class under study is access control and
> nothing else.

## The fix

Never look up an object from the full table — **filter by ownership first**, so
authorisation is part of the query rather than a forgotten afterthought:

```python
from django.shortcuts import get_object_or_404

# The lookup itself enforces ownership; a foreign id 404s.
note = get_object_or_404(Note, pk=pk, owner=request.user)
```

For richer rules than a single `owner` FK (team-shared objects, role-based
access), express the check with a scoped queryset or `UserPassesTestMixin` — see
the post. UUID primary keys raise the bar for enumeration but are **not** the
control: a leaked UUID still works without the ownership scope. The invariant:
**scope every lookup to the requester.**

## Isolation

This lab teaches IDOR and nothing else. The PK is a plain sequential integer **on
purpose** — enumerable identifiers are the surface the post is about. Output is
escaped (not an XSS lab, Post 2); there is no raw SQL (Post 1); the ownership
boundary is a single `owner` FK, not `is_staff`, so it does not drift into
privilege escalation (Post 7).

## Scanning it

The standard SAST tools **miss this class** — and for a deeper reason than a
missing plugin. Bandit reports **0 findings on the views**: its 42 plugin tests
are all dangerous-*call* checks (shell, `eval`, `mark_safe`, `yaml.load`…), none
models authorization, so an unscoped `get_object_or_404()` matches nothing. The
only thing it flags in the module is a `B106` hardcoded-password on the *test*
password — noise unrelated to the class. The Semgrep community packs report **0
findings** too (156 Python rules). Semgrep's own docs explain why, and it doubles
as the justification for a custom rule: IDOR "is the absence of an authorization
check," the vulnerable code "appears syntactically correct," and the fix is
"writing custom rules for your application that describe the access control logic
you're expecting" ([Semgrep docs](https://docs.semgrep.dev/learn/vulnerabilities/idor)).

That is the §6.4.1 case where a **custom rule** earns its place:
[`rules/idor.yaml`](../../rules/idor.yaml), with its stem-paired fixture
[`rules/idor.py`](../../rules/idor.py). It flags `get_object_or_404` /
`get_list_or_404` calls with no `owner=`/`user=` scope — so it fires on the
vulnerable view (line 23) and stays silent on the owner-scoped fix, the
scan-assert the standard tools couldn't give. A hermetic CI job runs
`semgrep --test` on the fixture and then that fire/silent assert on the two views.

Bandit and Semgrep are pinned but **not bundled in the lab image** (same as CI,
which installs them per-job). Either install them on the host —
`pip install bandit==1.9.4 semgrep==1.170.0` — or run any command below inside
the container by prefixing it, e.g.
`docker compose run --rm web sh -c "pip install -q bandit==1.9.4 && bandit -r labs/post_06_idor/"`.
All commands run from the repository root.

```bash
# the standard tools — miss the class (Bandit finds only a test-password false alarm)
bandit -r labs/post_06_idor/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_06_idor/

# the custom rule — catches it
semgrep --test --config rules/idor.yaml rules/idor.py
semgrep scan --config rules/idor.yaml labs/post_06_idor/views_vulnerable.py   # 1 finding (line 23)
semgrep scan --config rules/idor.yaml labs/post_06_idor/views_secure.py       # 0 findings
```

**No push-button DAST here.** IDOR is a runtime class, but a black-box scanner
walking `/idor/vulnerable/1/`, `/2/`, `/3/` sees three `200 OK`s and no error —
it has no way to know note 2 belongs to Bob and should have been off-limits to
Alice. Confirming IDOR automatically means teaching the tool the ownership model
(ZAP's access-control testing can *assist* with two authenticated sessions, but a
human supplies the intent). The full reasoning and captured runs are in
[`scans/`](scans/).
