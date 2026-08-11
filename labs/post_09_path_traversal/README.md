# Lab 09 — Path Traversal

Companion lab for the blog post
**[Path Traversal](https://thiagoteixeira.tech/blog/path-traversal-how-settings-py-escapes-your-media-directory-and-how-djangos-safe-join-stops-it/)**
(Series II).

| | |
|---|---|
| **OWASP** | A01:2021 — Broken Access Control |
| **CWE** | CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |
| **ASVS** | V12.3.1 — file paths from user input are validated to stay within the intended directory |
| **Detection** | SAST — the standard tools **miss** it; the Django community rule is registry-only *and* misses the realistic multi-variable form, so a **custom rule** ([`rules/path_traversal.yaml`](../../rules/path_traversal.yaml)) catches it, asserted in the hermetic CI job |

## The two views

A "download a document" helper that opens a file from a fixed document root by
the name given in `?file=`.

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | `open(os.path.join(DOCS_ROOT, name))` — the join does not contain the result |
| Secure | [`views_secure.py`](views_secure.py) | `safe_join(DOCS_ROOT, name)` → catch `SuspiciousFileOperation` → 404 |

`os.path.join` is a string concatenator: it never normalizes or checks the path.
A `../` segment climbs out of `DOCS_ROOT`, and an absolute component
(`/etc/passwd`) discards the base entirely. The flag lives in `flag.txt` **one
level above** `documents/` — the download feature, which should only ever serve
files inside `documents/`, has no legitimate way to reach it. A traversal payload
does.

The secure view swaps the join for Django's `safe_join`, which resolves the path
and verifies it still starts with the base, raising `SuspiciousFileOperation` if
not — turned into a generic 404 so the response never confirms the attempt.

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
docker compose exec web python manage.py seed_labs   # plants documents/ + the off-limits flag
```

On Windows PowerShell `curl` is an alias for `Invoke-WebRequest` — use `curl.exe`,
or Git Bash.

## Test the pair from the command line

**1. Climb out with `../`** — one `../` leaves `documents/` and reads the flag:

```bash
curl -s "http://127.0.0.1:8000/path-traversal/vulnerable/?file=../flag.txt"
# FLAG{path_traversal_via_unvalidated_path_join}
```

**2. Absolute-path injection** — the surprising variant: `os.path.join` throws the
base away when a component is absolute (the flag path is under the system temp
dir; substitute yours, or just use `../flag.txt` above):

```bash
curl -s "http://127.0.0.1:8000/path-traversal/vulnerable/?file=/etc/passwd" | head -1
# root:x:0:0:root:/root:/bin/sh   (any file the process can read)
```

**3. The fix holds** — `safe_join` rejects both payloads and returns 404:

```bash
curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8000/path-traversal/secure/?file=../flag.txt"
# 404
```

**4. The feature still works** — a legitimate name is served from `documents/`:

```bash
curl -s "http://127.0.0.1:8000/path-traversal/secure/?file=readme.txt"
# Public document. Nothing secret here.
```

Or prove all of it in one command (from the repo root):

```bash
docker compose run --rm web python manage.py test labs.post_09_path_traversal
```

## The fix

Never build a filesystem path from user input with `os.path.join` and open the
result. Use `django.utils._os.safe_join`, which raises `SuspiciousFileOperation`
when the resolved path escapes the base directory:

```python
from django.core.exceptions import SuspiciousFileOperation
from django.utils._os import safe_join

try:
    path = safe_join(DOCS_ROOT, name)   # raises if name escapes DOCS_ROOT
except SuspiciousFileOperation:
    raise Http404()
```

Stronger still, remove the filename from the URL entirely: look the file up
through a model instance's `FileField`/`Storage`, so the user supplies a
PK/UUID, not a path, and there is no path to traverse. (`safe_join` normalizes
lexically, not symlink-aware; if the served root can contain attacker-created
symlinks, resolve with `Path.resolve()` and check `is_relative_to(base)`. This
lab's root holds only inert seeded files, so `safe_join` is the right primitive.)

## Isolation

This lab teaches path traversal and nothing else. Files are served as
`text/plain`, so a traversed HTML document cannot turn this into an XSS demo. The
served root holds only inert text files. There is no authentication in the way —
the lesson is the *filename*, not the caller's identity (that is IDOR, Post 6);
adding `@login_required` would only make the `curl` walkthrough need a session
without changing what traversal does. The lab has **no database model** — the
state under study is the filesystem, so `seed.py` plants files instead of rows
(a documented deviation from the fixed skeleton).

## Scanning it

Path traversal via `os.path.join` looks like a class the standard tools must
catch. They do not — and the reason is the teaching point. Full evidence and the
reproduction under [`scans/`](scans/) and [`scans/README.md`](scans/README.md).

```bash
bandit -r labs/post_09_path_traversal/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_09_path_traversal/
semgrep scan --config rules/path_traversal.yaml labs/post_09_path_traversal/views_vulnerable.py
```

- **Bandit** → **0/0 on both views.** It has no path-traversal plugin, and it does
  no taint to connect `request.GET` → `os.path.join` → `open`.
- **Semgrep community** → **0/0.** A Django rule exists —
  `python.django.security.injection.path-traversal.path-traversal-join` — but it is
  **excluded from the curated packs** (the curated 156 rules fire 0 even on the
  one-liner it matches directly; the same tier exclusion as Lab 02 / Lab 08).
- **The registry rule, run directly, misses the *realistic* form.** It is a
  syntactic rule, and the OSS engine follows only **one** variable indirection: it
  fires on `open(os.path.join(base, request.GET.get(...)))` but is silent on the
  two-hop `name = request…` → `path = os.path.join(base, name)` → `open(path)` — the
  post's own Vulnerable Pattern 1 and how real download views are written. Bridging
  both hops is Semgrep Pro's interprocedural taint, absent from the community
  engine. An off-the-shelf rule exists that gives **false confidence.**
- **The custom rule** ([`rules/path_traversal.yaml`](../../rules/path_traversal.yaml))
  catches the realistic form and stays silent on the `safe_join` fix — the
  scan-assert this class otherwise can't have, enforced in the hermetic CI job. Its
  one honest limit (a source-agnostic false positive on a hardcoded-name join) is
  documented as `todook` in `rules/path_traversal.py`.

Path traversal is also a **DAST** class — the `curl` walkthrough above is the
dynamic probe (an OWASP ZAP path-traversal scan or a `../`-fuzz would do the same).
No automated DAST transcript is committed: ZAP is a heavy daemon against the
command-line-first convention, and `tests.py` plus the `curl` demo are the
deterministic dynamic proof.

Bandit and Semgrep are pinned but **not bundled in the lab image**. Install them
on the host — `pip install bandit==1.9.4 semgrep==1.170.0` — and run them there;
SAST reads the source directly. All commands run from the repository root.
