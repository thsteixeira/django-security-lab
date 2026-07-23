# Captured scan evidence — Lab 01 (SQL Injection)

These are the **real, unedited scanner runs** behind the post's detection
section. They are committed so you can read exactly what each tool reported
without booting the lab or installing anything — and so the claims can't be
bluffed. Each file starts with a header giving the exact command, tool version,
and date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | ✅ yes | `B608` on the vulnerable view (line 26); nothing on the secure view |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 (`p/django`) | SAST | ✅ yes | 1 taint finding (`request` → `execute()`) on the vulnerable view; nothing on the secure view |
| [`sqlmap-vulnerable.txt`](sqlmap-vulnerable.txt) | sqlmap 1.10.7 | DAST | ❌ no | `?q=1` at **default** effort — injectable four ways (boolean-blind, error-based, stacked queries, time-blind); `sqli_flag` dumped |
| [`sqlmap-secure.txt`](sqlmap-secure.txt) | sqlmap 1.10.7 | DAST | ❌ no | same command vs the secure view — "not injectable"; the ORM gives it nothing |

## Why the DAST runs live here

**SAST runs in CI on every commit** (see [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml)),
so `bandit.txt` / `semgrep.txt` are reproduced automatically and are archived here
only for convenience. **DAST does not run in CI** — sqlmap needs a booted, seeded
instance and is slow and noisy — so `sqlmap-*.txt` are the permanent record of a
run performed once by hand. This is the standard split: static checks gate every
commit; the dynamic exploit is captured as evidence and reproduced by the reader
on demand.

## Reproducing them

SAST needs no server:

```bash
bandit -r labs/post_01_sql_injection/
semgrep scan --config p/django labs/post_01_sql_injection/
```

DAST needs the lab booted (`docker compose up`). Point sqlmap at the vulnerable
endpoint — no raised effort is needed against Postgres. At its **default**
`--level=1 --risk=1`, sqlmap fingerprints the DBMS as PostgreSQL and confirms
`?q=1` injectable four ways (boolean-based blind, error-based, stacked queries,
and time-based blind), then dumps the flag table the search should never reach:

```bash
sqlmap -u 'http://127.0.0.1:8000/sql-injection/vulnerable/?q=1' \
       -p q --batch --dump -T sqli_flag
```

The **same** command against `/sql-injection/secure/` reports *"all tested
parameters do not appear to be injectable"* — the ORM parameterises, so sqlmap
finds nothing. That vulnerable-vs-secure pair, at identical settings, is the
lesson.

## A note on normalization

The sqlmap logs were captured against the canonical `docker compose` stack
(PostgreSQL 16, the app on port `8000`). One cosmetic substitution was applied
for this public repo, disclosed in each file's header: the absolute local
`--output-dir` path → `<output-dir>`. Nothing else was changed — the payloads,
findings, DBMS fingerprint, and dumped flag are verbatim.
