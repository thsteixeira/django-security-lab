# Captured scan evidence — Lab 12 (Session Fixation)

These are the **real, unedited runs** behind the post's detection section. Each
file starts with a header giving the exact command, tool version, and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`check_deploy.txt`](check_deploy.txt) | Django `check --deploy` | framework scanner | — | `security.W012` flags the missing `SESSION_COOKIE_SECURE` — the cookie half, named as a hijacking risk |
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | — | **0 findings** — no dangerous call to match |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 | SAST | — | community **0**; registry tier **5 unrelated nits**, nothing about rotation |

## Why the SAST tools miss this — and why no custom rule fits

Session fixation is the sharpest "no rule can find this" case in the series,
because there are **two** flaws and neither is a pattern:

1. **The rotation flaw is the *absence* of a call.** The vulnerable view fails by
   *not* calling `login()`/`cycle_key()`. A static rule can flag a dangerous call;
   it cannot flag a missing one. There is no syntactic shape to write a rule
   against — the same wall Lab 11 hit — so this lab ships **no custom rule**
   (§6.4.1), consistent with the "don't fake a rule" principle.

2. **The cookie flaw is a *setting*, not code.** `SESSION_COOKIE_SECURE = False`
   is a value, not a call site. Bandit and the Semgrep code rules don't inspect
   settings values.

**Bandit** is 0/0 (not even the usual test-password noise — the lab imports the
shared cast password instead of hard-coding one). **Semgrep community** is 0/156.
The **registry/audit tier** reports 5 findings, all unrelated: the
`direct-use-of-httpresponse` audit XSS nit on the lab's plain `HttpResponse`
views (the same nit Labs 08/11 surface) plus one maintainability nit.

## What *does* catch it

The cookie half has a scanner after all — **Django's own**, `manage.py
check --deploy`, which ships in the framework and flags `security.W012`:

> `SESSION_COOKIE_SECURE is not set to True. Using a secure-only session cookie
> makes it more difficult for network traffic sniffers to hijack user sessions.`

That is the Firesheep lesson in Django's own words. The other four warnings
(`W001`/`W002`/`W003`/`W018`) are the general deploy checklist for this lab's
minimal settings.

The **rotation half** has no scanner — its proof is dynamic and deterministic:
`tests.py` asserts `session_key` *changes* across `login()` (and stays the same on
the vulnerable view), and the README's `curl` walkthrough fixes an id, rides it to
the flag on the vulnerable view, and is bounced (302) on the secure one.

## DAST

Session fixation is runtime-observable, so it is DAST-shaped — a scanner with two
sessions could fix an id and check whether it survives login. But the check needs
a notion of *which* id was pre-chosen and *whose* account it lands in, which is
threat-model knowledge, not a signature. The README `curl` walkthrough **is** that
dynamic probe, reproducible from a clone; no separate automated-scanner transcript
is committed. Like all DAST here, it would not run in CI.

## Reproducing

```bash
docker compose up -d && docker compose exec web python manage.py seed_labs
docker compose run --rm web python manage.py check --deploy   # W012
bandit -r labs/post_12_session_fixation/                       # 0
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_12_session_fixation/   # 0
docker compose run --rm web python manage.py test labs.post_12_session_fixation   # the deterministic proof
```
