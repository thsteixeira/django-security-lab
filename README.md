# django-security-lab

[![CI](https://github.com/thsteixeira/django-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/thsteixeira/django-security-lab/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Runnable Django labs for the OWASP Top 10, each scanned with the off-the-shelf
tools a security analyst actually runs — Bandit and Semgrep (SAST), sqlmap / OWASP
ZAP (DAST, where the class fits), pip-audit (SCA) — green in CI on every commit.**

This is the companion repository for
**[Secure by Design](https://thiagoteixeira.tech/series/secure-by-design/)** — a
Django web application security series, also available in
**[Portuguese](https://thiagoteixeira.tech/pt-br/series/secure-by-design/)**. Each
post explains one attack; the matching lab here is the proof you can re-run: a
vulnerable view and a secure view, plus the exact commands and captured output the
post quotes.
Clone it, boot the lab, and exercise the vulnerable→secure pair **from the
command line** — `curl` for the request/response, the standard scanners for
detection, `manage.py test` as the gate. No browser required.

> ⚠️ **Intentionally vulnerable — never deploy this publicly.** Some modules
> execute attacker input and produce real RCE. Run it only on localhost or via
> the provided Docker stack (every port bound to `127.0.0.1`), never with real
> data. See [SECURITY.md](SECURITY.md).

## Why this exists

A Django-5.x security lab mapped to OWASP / CWE / ASVS, with reproducible
SAST/DAST/SCA playbooks and a green CI pipeline, **did not exist**. The
alternatives are dated or off-platform: django.nV is pinned to old Django, DVWA
is PHP, Juice Shop is Node, WebGoat is Java. This repo fills that gap for the
Python/Django ecosystem — a lab you clone and scan with the tools you already
have on hand.

## What's inside

```
labs/post_NN_<topic>/   runnable vulnerable + secure views, a CTF flag, tests, a teaching README
rules/<topic>.{yaml,py} OPTIONAL — a custom Semgrep rule + its test fixture, present only for the
                        rare post where the standard tools miss a Django-specific pattern (see below)
```

| # | Post / topic | Lab | Detection |
|---|---|---|---|
| 01 | SQL Injection | [`labs/post_01_sql_injection/`](labs/post_01_sql_injection/) | SAST (Bandit + Semgrep community) · DAST (sqlmap) |
| 02 | Cross-Site Scripting (XSS) | [`labs/post_02_xss/`](labs/post_02_xss/) | SAST — the standard tools can't split bug from fix, so a **custom rule** ([`rules/xss.yaml`](rules/xss.yaml)) does, asserted in a hermetic CI job |
| 03 | Server-Side Template Injection (SSTI) | [`labs/post_03_ssti/`](labs/post_03_ssti/) | SAST — the standard tools **miss** the `Template()` sink entirely, so a **custom rule** ([`rules/ssti.yaml`](rules/ssti.yaml)) catches it, asserted in the same hermetic CI job |
| 04 | OS Command Injection ⚠️ tier 3 | [`labs/post_04_command_injection/`](labs/post_04_command_injection/) | SAST — Bandit `B602` (shell=True) and Semgrep community both **catch** it (fire on vulnerable, silent on secure), asserted in CI; no custom rule (cf. SQLi) |
| 05 | XXE (XML External Entity) | [`labs/post_05_xxe/`](labs/post_05_xxe/) | SAST — the standard tools flag the *stdlib* parsers but **miss lxml** (Bandit's `B410` was removed; Semgrep community + registry are 0), so a **custom rule** ([`rules/xxe.yaml`](rules/xxe.yaml)) flags the lxml footgun, asserted in the hermetic CI job |
| 06 | Broken Access Control / IDOR | [`labs/post_06_idor/`](labs/post_06_idor/) | SAST — the standard tools **miss** owner-unscoped lookups (a semantic authz flaw), so a **custom rule** ([`rules/idor.yaml`](rules/idor.yaml)) catches it, asserted in the same hermetic CI job |
| 07 | Privilege Escalation (mass assignment) | [`labs/post_07_privesc/`](labs/post_07_privesc/) | SAST — the standard tools **miss** `fields='__all__'` (linter, not SAST, territory), so a **custom rule** ([`rules/mass_assignment.yaml`](rules/mass_assignment.yaml)) catches it, asserted in the same hermetic CI job |
| 08 | Cross-Site Request Forgery (CSRF) | [`labs/post_08_csrf/`](labs/post_08_csrf/) | SAST — curated packs **miss** `@csrf_exempt`; Semgrep's own **audit-tier** rule (`no-csrf-exempt`) catches it, so **no custom rule** — asserted in the SAST job |
| 09 | Path Traversal | [`labs/post_09_path_traversal/`](labs/post_09_path_traversal/) | SAST — Bandit 0/0; the Django community rule is **registry-only** *and* its OSS engine **misses the realistic multi-variable form** (Pro-taint territory), so a **custom rule** ([`rules/path_traversal.yaml`](rules/path_traversal.yaml)) catches it, asserted in the hermetic CI job |
| 10 | Mass Assignment (DRF) | [`labs/post_10_mass_assignment/`](labs/post_10_mass_assignment/) | SAST — the standard tools **miss** `fields='__all__'` (Bandit 0; Semgrep community *and* registry 0), so the **custom rule** ([`rules/mass_assignment.yaml`](rules/mass_assignment.yaml)) — **shared with Lab 07** — catches it on the DRF serializer, asserted in the hermetic CI job |
| 11 | Brute Force & Credential Stuffing | [`labs/post_11_brute_force/`](labs/post_11_brute_force/) | **No SAST tier finds it** (wrong-key + missing-control) — the gate is `tests.py` and a dynamic `curl` XFF-rotation probe |

## Run the labs

Docker + Postgres is the canonical path — what a reader runs matches what CI runs.
Run every `docker compose` command from the **repository root** (the folder with
`docker-compose.yml`):

```bash
docker compose up -d --build       # Postgres + Django on http://127.0.0.1:8000
```

Each lab's README then walks the vulnerable→secure pair from the command line
with `curl` — post the payload, read the exploit succeed against `/vulnerable/`,
read it fail against `/secure/`. Start with
[`labs/post_01_sql_injection/`](labs/post_01_sql_injection/).

Run the test suite against that same stack — the universal gate, and the
one-command proof for every lab:

```bash
docker compose run --rm web python manage.py test
```

## Scan the labs with the standard tools

Detection is **standard tools first** — the same scanners a CySA+ analyst runs,
pointed at each lab. Each lab README shows the exact commands and captured output.

The scanners are **not bundled in the image** (CI installs them per-job, pinned).
Install what you need on the host — `pip install bandit==1.9.4 semgrep==1.170.0 pip-audit==2.9.0`
(sqlmap ships separately) — and run them there. The `web` container is
deliberately network-isolated for tier-3 containment (see [SECURITY.md](SECURITY.md)),
so it cannot `pip install` a scanner; the host is the right place anyway, since
SAST reads the source files and DAST hits the published port.

```bash
# SAST — static analysis of the source
bandit -r labs/post_01_sql_injection/
semgrep scan --config p/django labs/post_01_sql_injection/

# SCA — known-CVE audit of the dependencies
pip-audit -r requirements.txt

# DAST — dynamic scan against the booted lab (full walkthrough in the lab README)
sqlmap -u 'http://127.0.0.1:8000/sql-injection/vulnerable/?q=1' \
       -p q --batch --dump -T sqli_flag
```

CI runs the Django lab tests (the universal gate) plus Bandit + Semgrep-community
(SAST) and pip-audit (SCA). DAST is captured in the lab README and reproduced by
the reader, not run in CI.

### Custom Semgrep rules are the exception, not the rule

Most classes are well covered by Bandit and the Semgrep community packs, so most
labs ship **no** custom rule. A hand-written rule appears under `rules/` only
where the standard tools fall short on a Django-specific pattern — either they
*miss* it (mass assignment, IDOR, privilege escalation) or they *can't separate
the bug from the fix*. SQL injection (Lab 01) needs none: the standard tools
catch it. Several do:

- **XSS-via-`mark_safe` (Lab 02)** — the *can't-distinguish* case: Bandit flags
  both the vulnerable and the fixed view, community Semgrep flags neither, so
  [`rules/xss.yaml`](rules/xss.yaml) supplies the rule that tells them apart.
- **SSTI-via-`Template()` (Lab 03)** — the *miss* case: Bandit and community
  Semgrep both report nothing at all (neither models the `Template()` sink), so
  [`rules/ssti.yaml`](rules/ssti.yaml) supplies the only rule that fires.
- **XXE-via-`lxml` (Lab 05)** — the *miss* case with an inversion: Bandit flags
  the **stdlib** parsers (`B405`/`B314`) but its lxml check `B410` was removed, so
  it's 0/0 on the lxml view; Semgrep community and the full registry are 0 too. The
  parser the tools catch is the one modern Python already hardened; **lxml**, the
  one that still performs the file read, is invisible — so
  [`rules/xxe.yaml`](rules/xxe.yaml) flags the lxml footgun and stays silent on the
  `defusedxml` fix.
- **IDOR (Lab 06)** — the *miss* case again, for a deeper reason: it's a semantic
  authorization flaw (the vulnerable and fixed code differ only by
  `owner=request.user`), so Bandit ships no plugin for it and community Semgrep
  covers it with none — Semgrep's own docs say the answer is a custom rule, which
  [`rules/idor.yaml`](rules/idor.yaml) supplies.
- **Privilege escalation / mass assignment (Labs 07 & 10)** — the *miss* case:
  neither Bandit nor community Semgrep (nor the registry `r/python.django`) flags
  `fields='__all__'` — that pattern is caught by Django *linters* (Ruff `DJ007`,
  flake8-django `DJ07`), not this SAST toolchain — so
  [`rules/mass_assignment.yaml`](rules/mass_assignment.yaml) supplies it, shared
  by both posts (07 exposes a permission field, 10 a non-permission one).
- **Path traversal (Lab 09)** — the *miss* case with a twist worth knowing: a
  Django rule *does* exist in the Semgrep registry
  (`python.django.security.injection.path-traversal.path-traversal-join`), but it is
  **excluded from the curated packs** *and*, run directly, its OSS engine follows
  only one variable indirection — so it misses the realistic two-hop
  `request → name → os.path.join → path → open` form (the blog post's own vulnerable
  pattern; bridging both hops needs Semgrep Pro's interprocedural taint). Bandit has
  no path-traversal plugin at all. So the shipped rule gives *false confidence*, and
  [`rules/path_traversal.yaml`](rules/path_traversal.yaml) supplies the one that
  catches realistic code — keyed on the `os.path.join → open` hop and silent on the
  `safe_join` fix.

**Not every gap needs a custom rule.** **CSRF (Lab 08)** is the counter-example:
the curated packs miss `@csrf_exempt`, but Semgrep already ships a rule for it in
the **audit tier** (`r/python.django…audit.csrf-exempt.no-csrf-exempt`) that
fires on the exempt view and stays silent on `@csrf_protect`. Writing our own
would duplicate it — so Lab 08 ships no rule and instead teaches *audit-tier
awareness*: run the audit tier, not just the default pack. The detection pass
always checks that tier before deciding a rule is warranted.

**Sometimes no tier finds it at all.** **Brute force (Lab 11)** is the honest
floor: Bandit, the community packs, *and* the audit tier all report nothing on
the login views, because both flaws are unmatchable by static analysis — a
rate-limit keyed on the *wrong* value (a semantic judgement about who controls
`X-Forwarded-For`) and the *absence* of a per-account control (there is no code
to match). So Lab 11 ships no rule and no SAST scan-assert; its signal is
**dynamic** — a `curl` loop that rotates a forged header and watches the limit
fail to trigger — and its gate is `tests.py`. The lesson is the one CySA+ keeps
returning to: some findings come from a threat-model review and a probe, not a
scanner.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a lab (and, rarely, a custom
rule). Issues for scanner false positives / false negatives are welcome.

## License

MIT — see [LICENSE](LICENSE).
