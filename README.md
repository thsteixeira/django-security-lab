# django-security-lab

[![CI](https://github.com/thsteixeira/django-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/thsteixeira/django-security-lab/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Runnable Django labs for the OWASP Top 10, each scanned with the off-the-shelf
tools a security analyst actually runs — Bandit and Semgrep (SAST), OWASP ZAP /
sqlmap (DAST), pip-audit (SCA) — green in CI on every commit.**

This is the companion repository for the
[Django Security Series](https://thiagoteixeira.tech/blog/). Each post explains
one attack; the matching lab here is the proof you can re-run: a vulnerable view
and a secure view, plus the exact scanner commands and captured output the post
quotes. Clone it, boot the lab, point the standard tools at it, and watch them
flag the vulnerable view and stay silent on the secure one.

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

## Run the labs

Docker + Postgres is the canonical path — what a reader runs matches what CI runs:

```bash
docker compose up --build          # Postgres + Django on http://127.0.0.1:8000
```

Then open `http://127.0.0.1:8000/sql-injection/vulnerable/` and try the exploit
in that lab's README.

Local, without Docker (SQLite, for a quick look or the fast test loop):

```bash
python -m venv .venv && . .venv/Scripts/activate   # or source .venv/bin/activate
pip install -r requirements.txt
LAB_DB=sqlite python manage.py migrate
LAB_DB=sqlite python manage.py test
```

## Scan the labs with the standard tools

Detection is **standard tools first** — the same scanners a CySA+ analyst runs,
pointed at each lab. Each lab README shows the exact commands and captured output.

```bash
# SAST — static analysis of the source
bandit -r labs/post_01_sql_injection/
semgrep scan --config p/django labs/post_01_sql_injection/

# SCA — known-CVE audit of the dependencies
pip-audit -r requirements.txt

# DAST — dynamic scan against the booted lab (full walkthrough in the lab README)
# Note: at default effort sqlmap calls this a false positive; --level/--risk find it.
sqlmap -u 'http://127.0.0.1:8000/sql-injection/vulnerable/?q=1' \
       -p q --batch --level=5 --risk=3 --dump -T sqli_flag
```

CI runs the Django lab tests (the universal gate) plus Bandit + Semgrep-community
(SAST) and pip-audit (SCA). DAST is captured in the lab README and reproduced by
the reader, not run in CI.

### Custom Semgrep rules are the exception, not the rule

Most classes are well covered by Bandit and the Semgrep community packs, so most
labs ship **no** custom rule. A hand-written rule appears under `rules/` only for
the rare Django-specific pattern the standard tools miss (mass assignment, IDOR,
privilege escalation) — see [CONTRIBUTING.md](CONTRIBUTING.md). SQL injection is
covered by the standard tools, so Lab 01 has no custom rule.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a lab (and, rarely, a custom
rule). Issues for scanner false positives / false negatives are welcome.

## License

MIT — see [LICENSE](LICENSE).
