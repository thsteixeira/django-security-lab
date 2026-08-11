# Lab 03 — Server-Side Template Injection (SSTI)

Companion lab for the blog post
**[Server-Side Template Injection (SSTI): When Django Templates Become a Weapon](https://thiagoteixeira.tech/blog/server-side-template-injection-ssti-when-django-templates-become-a-weapon/)**.

| | |
|---|---|
| **OWASP** | A03:2021 — Injection |
| **CWE** | CWE-1336 — Improper Neutralization of Special Elements Used in a Template Engine |
| **ASVS** | V5.2.5 — protect against template injection |
| **Detection** | SAST — the standard tools **miss** this class; a **custom rule** ([`rules/ssti.yaml`](../../rules/ssti.yaml)) catches it, asserted in CI (see Scanning it) |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The two views

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | `Template(tpl).render(...)` — compiles the user's `?tpl=` string **as the template source** |
| Secure | [`views_secure.py`](views_secure.py) | `Template("{{ message }}").render(Context({"message": tpl}))` — the same input, passed in **as data** |

Both are a "render a greeting" feature. The only difference is who controls the
template *source*: in the vulnerable view the user does, so any name they write
is resolved against the view's context — including `flag`, a value seeded into
the context that the greeting feature was never meant to expose. Both views hold
the **same context** (`flag` included), which is the point: the fix is
structural, not a matter of keeping the secret out of the context.

This is the **DTL** case, and deliberately so. Django's template language does
not evaluate Python expressions — `{{7*7}}` raises `TemplateSyntaxError` at parse
time — so there is **no RCE here**. SSTI in DTL is *context disclosure* (and
template-tag invocation), which is exactly the boundary the post draws. The RCE
version needs a Jinja2 backend (Pattern 2 in the post), which this lab does not
ship.

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
```

Everything below is `curl` against that stack — no browser needed. Run the `curl`
commands in a POSIX shell (Linux, macOS, WSL, or **Git Bash** on Windows). Two
things matter:

- **`-g` is required.** SSTI payloads contain `{` and `}`, which curl otherwise
  treats as glob characters and rejects. `-g` (`--globoff`) turns that off.
- On Windows PowerShell, `curl` is an alias for `Invoke-WebRequest` — use
  `curl.exe` instead, or just switch to Git Bash.

## Test the pair from the command line

**1. The feature working as intended.** The vulnerable view renders your `?tpl=`
as a template, so the seeded `name` context variable resolves:

```bash
curl -sg 'http://127.0.0.1:8000/ssti/vulnerable/?tpl={{name}}' | grep -o '<p>world</p>'
# <p>world</p>
```

**2. Exploit it.** Because the user controls the template source, `{{flag}}`
resolves against the context and the secret comes back:

```bash
curl -sg 'http://127.0.0.1:8000/ssti/vulnerable/?tpl={{flag}}' | grep -o 'FLAG{[^}]*}'
# FLAG{ssti_user_input_compiled_as_template}
```

**3. The same payload against the secure view.** Here `?tpl=` is passed as *data*
into the fixed `{{ message }}` template. DTL substitutes it as a string and never
re-parses it, so the payload comes back **literal** — the secret is never reached,
even though `flag` is in the context exactly as before:

```bash
curl -sg 'http://127.0.0.1:8000/ssti/secure/?tpl={{flag}}' | grep -o '{{flag}}'
# {{flag}}
curl -sg 'http://127.0.0.1:8000/ssti/secure/?tpl={{flag}}' | grep -c 'FLAG{ssti'
# 0
```

**4. The wrong probe.** `{{7*7}}` is the classic SSTI probe, but against DTL it
proves nothing — the parser rejects arithmetic before rendering, so the request
500s with a `TemplateSyntaxError` rather than returning `49`:

```bash
curl -sg 'http://127.0.0.1:8000/ssti/vulnerable/?tpl={{7*7}}' | grep -o 'TemplateSyntaxError' | head -1
# TemplateSyntaxError
```

The real test in DTL is *what named objects are in the context*, not whether
arithmetic evaluates.

Or prove all of it in one command (from the repo root):

```bash
docker compose run --rm web python manage.py test labs.post_03_ssti
```

> **Why `curl`, not a browser.** The bug is server-side: a value from the render
> context comes back in the HTTP response on one view and not the other, which
> `grep` shows plainly. The rendered output is HTML-escaped before it reaches the
> response, so a `<script>` in the template source cannot turn this into an XSS
> demo — the class under study is template injection and nothing else.

## The fix

User input is context **data**, never template **source**. Keep the template a
fixed literal (or a file you load with `get_template`) and pass user values
through the context:

```python
from django.template import Context, Template

# The template source is yours; the user's value is data.
Template("{{ message }}").render(Context({"message": user_input}))
```

If a feature genuinely needs user-authored template logic, that is the one case
for `jinja2.sandbox.SandboxedEnvironment` with a minimal context — see the post.
The invariant: **a template is a file you control, not a string a user sends you.**

## Isolation

This lab teaches SSTI and nothing else. The rendered output is escaped, so a
`<script>` payload cannot make it an XSS lab (that is Post 2); it is DTL-only, so
it cannot become an RCE lab (the Jinja2 escalation is explained in the post, not
run here); and input arrives by GET with no form, so it does not drift into CSRF
(Post 8).

## Scanning it

The standard SAST tools **miss this class entirely** — Bandit reports **0
findings** (it has no plugin for the `Template()` sink) and the Semgrep community
packs report **0 findings** too (156 Python rules, none covering this Django
sink). Neither fires on the vulnerable view, so there is no scan-assert to be had
without a rule of our own. That is the §6.4.1 case where a **custom rule** earns
its place: [`rules/ssti.yaml`](../../rules/ssti.yaml), with its stem-paired
fixture [`rules/ssti.py`](../../rules/ssti.py). It flags a `Template()` /
`from_string()` compiled from a value that is not a string literal — so it fires
on the vulnerable view and stays silent on the secure one (whose source *is* a
literal), the scan-assert the standard tools couldn't give. A hermetic CI job
runs `semgrep --test` on the fixture and then that fire/silent assert on the two
views.

Bandit and Semgrep are pinned but **not bundled in the lab image** (same as CI,
which installs them per-job). Install them on the host —
`pip install bandit==1.9.4 semgrep==1.170.0` — and run the commands below there.
The `web` container is network-isolated for tier-3 containment (see
[SECURITY.md](../../SECURITY.md)), so it cannot `pip install` a scanner; the host
is the right place anyway, since SAST reads the source files directly. All
commands run from the repository root.

```bash
# the standard tools — miss this entirely
bandit -r labs/post_03_ssti/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_03_ssti/

# the custom rule — catches it
semgrep --test --config rules/ssti.yaml rules/ssti.py
semgrep scan --config rules/ssti.yaml labs/post_03_ssti/views_vulnerable.py   # 1 finding
semgrep scan --config rules/ssti.yaml labs/post_03_ssti/views_secure.py       # 0 findings
```

**No DAST here.** SSTI has URL-driven scanners (SSTImap, tplmap, Nuclei, ZAP),
but they confirm injection by making the engine *evaluate* a probe — and DTL
never does, so against this DTL-only lab they all report *not injectable*.
Expression-probe DAST is blind to DTL's disclosure-class SSTI; it becomes real
only against a Jinja2 backend. The full reasoning and captured runs are in
[`scans/`](scans/).
