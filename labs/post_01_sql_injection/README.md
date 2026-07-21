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

## Capture the flag

Run the stack (`docker compose up`, then browse to
`http://127.0.0.1:8000/sql-injection/vulnerable/`) and pass this as `q`:

```
' UNION SELECT id, 'x', value FROM sqli_flag -- 
```

The query the view sends becomes:

```sql
SELECT id, title, body FROM sqli_note WHERE title LIKE '%' UNION SELECT id, 'x', value FROM sqli_flag -- %'
```

The `'%'` closes the intended `LIKE` literal, the `UNION` appends every row of
`sqli_flag`, and `-- ` comments out the trailing `%'`. The flag
`FLAG{sql_injection_via_raw_string_interpolation}` appears in the results.

Send the **same** payload to `/sql-injection/secure/` and nothing leaks: the ORM
binds it as a single literal search string, so it matches no note titles and
never reaches `sqli_flag`.

`tests.py` asserts both outcomes — it is the runnable proof, not a screenshot.

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

Boot the lab (`docker compose up`, or the SQLite dev loop), then point sqlmap at
the vulnerable endpoint. A naive run is misleading: `?q=1 --batch` finds a UNION
point, then discards it as a *"false positive"* and reports the parameter not
injectable (see [`scans/sqlmap-default-bail.txt`](scans/sqlmap-default-bail.txt)).
The app *is* vulnerable — sqlmap's default effort level is simply too conservative
for this endpoint (the parameter is wrapped in `LIKE '%...%'`, the view reflects
the term, and malformed probes return HTTP 500). sqlmap tells you the fix itself:
*"Try to increase values for '--level'/'--risk'."* Do that — nothing else changes,
same `?q=1` — and it confirms the injection three ways and dumps the flag table
the search should never reach:

```bash
sqlmap -u 'http://127.0.0.1:8000/sql-injection/vulnerable/?q=1' \
       -p q --batch --level=5 --risk=3 --dump -T sqli_flag
```

```
Parameter: q (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: q=1' OR NOT 6636=6636-- dRbP

    Type: time-based blind
    Title: SQLite > 2.0 OR time-based blind (heavy query)
    Payload: q=1' OR 3313=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(...))))-- Verv

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: q=1' UNION ALL SELECT NULL,CHAR(...),NULL-- Snen
back-end DBMS: SQLite
Table: sqli_flag
[1 entry]
+----+--------------------------------------------------+
| id | value                                            |
+----+--------------------------------------------------+
| 4  | FLAG{sql_injection_via_raw_string_interpolation} |
+----+--------------------------------------------------+
```

At the **same** `--level=5 --risk=3` settings, `/sql-injection/secure/` reports
*"all tested parameters do not appear to be injectable"* — the ORM's
parameterisation gives sqlmap nothing to work with. One honest note from the run:
the raw-SQL view returns HTTP 500 on sqlmap's malformed probes (unbalanced quotes
become database syntax errors), which sqlmap logs — a realistic sign of a view
executing attacker-shaped SQL. Full output:
[`scans/sqlmap-vulnerable.txt`](scans/sqlmap-vulnerable.txt),
[`scans/sqlmap-secure.txt`](scans/sqlmap-secure.txt).

### Why no custom rule

SQL injection is old and thoroughly covered: Bandit's `B608` and the Semgrep
community pack both catch it, and sqlmap proves it end to end. Writing a bespoke
Semgrep rule here would be busywork. A custom rule earns its place only on a
genuinely Django-specific pattern the standard tools don't model — mass
assignment, IDOR, privilege escalation — which is where a later lab will ship one
(see [CONTRIBUTING.md](../../CONTRIBUTING.md)). This lab ships none.
