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
| [`sqlmap-vulnerable.txt`](sqlmap-vulnerable.txt) | sqlmap 1.10.7 | DAST | ❌ no | `?q=1` at `--level=5 --risk=3` — injectable three ways (boolean/time-blind + UNION); `sqli_flag` dumped |
| [`sqlmap-secure.txt`](sqlmap-secure.txt) | sqlmap 1.10.7 | DAST | ❌ no | same settings vs the secure view — "not injectable"; the ORM gives it nothing |
| [`sqlmap-default-bail.txt`](sqlmap-default-bail.txt) | sqlmap 1.10.7 | DAST | ❌ no | the misleading first run: at default effort, sqlmap discards a real injection as a "false positive" |

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

DAST needs the lab booted (`docker compose up`, or the SQLite dev loop). The
`sqlmap-default-bail.txt` → `sqlmap-vulnerable.txt` pair is the lesson, and the
**only** thing that changes between them is the effort level. At its default
`--level=1 --risk=1`, sqlmap finds a UNION point on `?q=1` and then *discards it
as a false positive* — this endpoint is a low-signal target (the parameter is
wrapped in `LIKE '%...%'`, the view reflects the search term, malformed probes
return HTTP 500). sqlmap's own output names the fix: *"Try to increase values for
'--level'/'--risk'."* Do that and the **same** `?q=1` is confirmed three ways and
dumps the flag:

```bash
sqlmap -u 'http://127.0.0.1:8000/sql-injection/vulnerable/?q=1' \
       -p q --batch --level=5 --risk=3 --dump -T sqli_flag
```

## A note on normalization

The sqlmap logs were captured on a local dev instance. Two cosmetic
substitutions were applied for this public repo, disclosed in each file's header:
absolute local output paths → `<output-dir>` / `<home>`, and the local port
`8010` → the documented `8000`. Nothing else was changed — the payloads,
findings, DBMS fingerprint, and dumped flag are verbatim.
