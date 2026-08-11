# Lab 04 — OS Command Injection

> ⚠️ **TIER 3 — real remote code execution.** ("Tier 3" is this repo's own risk
> label for a lab that reaches real code/command execution; the tiers are defined
> in [SECURITY.md](../../SECURITY.md).) The vulnerable view runs
> attacker-controlled shell commands. Run it **only** inside the provided Docker
> stack, where `web` is a non-root user with **no network egress** (B6 — see
> [SECURITY.md](../../SECURITY.md)). Never run this on a host you care about or
> with real data.

Companion lab for the blog post
**[OS Command Injection](https://thiagoteixeira.tech/blog/)** (Series I).

| | |
|---|---|
| **OWASP** | A03:2021 — Injection |
| **CWE** | CWE-78 — Improper Neutralization of Special Elements used in an OS Command |
| **ASVS** | V5.3.8 — prevent OS command injection; use parameterized OS calls |
| **Detection** | SAST — Bandit `B602` (shell=True) **and** Semgrep community both fire on the vulnerable view and are silent on the secure one, asserted in CI (no custom rule needed; cf. Lab 01 / SQLi) |

## The two views

An "inspect this upload" helper that runs `wc -c` on a filename to report its
size.

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | `subprocess.run(f"wc -c {name}", shell=True)` — the filename is interpolated into a shell string |
| Secure | [`views_secure.py`](views_secure.py) | `subprocess.run(["wc", "-c", path], shell=False)` — the filename is one literal argument |

Both run with the upload directory as the working directory. The flag lives in
`flag.txt` **one level above** uploads/ — the inspector, which only ever `wc`s a
file inside uploads/, has no legitimate way to read it. A shell metacharacter in
the vulnerable view escapes the `wc` command and runs a second one that does.

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
```

The seed writes `uploads/sample.txt` and the off-limits `flag.txt`. On Windows
PowerShell `curl` is an alias for `Invoke-WebRequest` — use `curl.exe`, or Git
Bash.

## Test the pair from the command line

**1. Inject a second command** — the `;` ends the `wc` call and starts a `cat`
that reads the flag above uploads/:

```bash
curl -s -X POST http://127.0.0.1:8000/command-injection/vulnerable/ \
  --data-urlencode "name=sample.txt; cat ../flag.txt" | grep -o 'FLAG{[^}]*}'
# FLAG{command_injection_via_shell_true}
```

**2. The fix holds** — the same payload against the secure view is passed to `wc`
as a single (nonexistent) filename; no second command runs:

```bash
curl -s -X POST http://127.0.0.1:8000/command-injection/secure/ \
  --data-urlencode "name=sample.txt; cat ../flag.txt" | grep -o 'FLAG{[^}]*}'
# (nothing — wc reports "No such file or directory")
```

**3. The feature still works** — a legitimate filename returns its byte count:

```bash
curl -s -X POST http://127.0.0.1:8000/command-injection/secure/ \
  --data-urlencode "name=sample.txt"
# ... 29 /data/cmdinj/uploads/sample.txt
```

Or prove all of it in one command (from the repo root):

```bash
docker compose run --rm web python manage.py test labs.post_04_command_injection
```

## The fix

Never build a shell command string from user input. Pass the program and its
arguments as a **list** with `shell=False` (the default) so the OS executes one
program with your arguments verbatim — no shell parses metacharacters, so `;`,
`|`, `$( )`, and backticks are inert. If you genuinely need a shell feature,
validate the input against a strict allow-list first; do not try to "escape" it.

```python
subprocess.run(["wc", "-c", path], shell=False)   # arguments, not a shell string
```

## Isolation

This lab teaches OS command injection and nothing else. The invoked binary is
`wc`, a coreutil already in the base image — **no ImageMagick/ffmpeg**, so there
is no second CVE surface (the upload-processing chain is Post 25). Output is
HTML-escaped. The secure view passes the filename straight to `wc` as data; it is
not a path-traversal lesson (that is Post 9), so it does not add a traversal
guard — `shell=False` is the whole point here.

## Scanning it

Unlike the Django-specific classes in this series, command injection is a
textbook sink the standard tools catch — so there is **no custom rule**, just a
scan-assert like Lab 01.

```bash
bandit -r labs/post_04_command_injection/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_04_command_injection/
```

**Bandit** walks the Python AST for `B`-numbered risky constructs. `B602`
(`subprocess … shell=True`, HIGH) fires on the vulnerable view and is **absent**
on the secure one — CI asserts that *specific* check by `test_id`, because
Bandit's low-severity `B603`/`B607`/`B404` fire on *any* subprocess call (safe or
not) and would otherwise make the secure view look non-silent. **Semgrep
community** (`p/python` subprocess rules) is the clean case: three findings on
the vulnerable view, **zero** on the secure one.

Command injection is also a **DAST** class — the `curl` walkthrough above is the
dynamic probe (a `commix` or ZAP injection scan would do the same). No automated
DAST transcript is committed: those tools are not pinned into the toolchain, and
`tests.py` plus the `curl` demo are the deterministic dynamic proof. Full
reasoning and the captured runs are under [`scans/`](scans/) and
[`scans/README.md`](scans/README.md).

Bandit and Semgrep are pinned but **not bundled in the lab image**. Install them
on the host — `pip install bandit==1.9.4 semgrep==1.170.0` — and run them there.
The `web` container is network-isolated for tier-3 containment (see
[SECURITY.md](../../SECURITY.md)), so it cannot `pip install` a scanner; the host
is the right place anyway, since SAST reads the source files directly. All
commands run from the repository root.
