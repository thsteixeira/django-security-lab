# Captured scan evidence — Lab 11 (Brute Force & Credential Stuffing)

These are the **real, unedited scanner runs** behind the post's detection
section. Each file starts with a header giving the exact command, tool version,
and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | ⚠️ scanned, not asserted | nothing on the views — only `B105` noise on the seeded weak password |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 (community **and** audit/registry) | SAST | ⚠️ scanned, not asserted | community 0/0; the audit tier finds only unrelated findings — **no rule for this class in any tier** |

## This is the lab where no scanner tier helps — and that is the point

Every other lab either has a standard-tool finding (SQLi), a custom rule (XSS,
SSTI, IDOR, mass assignment), or an audit-tier rule (CSRF). Lab 11 has **none**,
and it is the honest illustration that some controls are pure design/logic that
static analysis cannot see.

**Bandit** reports nothing on the views. Its only finding is `B105` on the
seed's deliberately weak `victim` password (`summer2024`) — noise unrelated to
the class. Bandit has no notion of "no rate limit" or "throttle keyed on the
wrong thing."

**Semgrep community** (`p/django`, `p/python`, `p/owasp-top-ten`) — **0 findings**
across the module (156 rules).

**Semgrep's audit/registry tier** (`r/python.django`, `r/python`; 372 rules) —
checked because a rule can hide in the audit tier (that is the CSRF lab's whole
lesson). Here it finds only **unrelated** findings: `unvalidated-password` on the
seed's `set_password`, and the XSS audit rule `direct-use-of-httpresponse` on the
views. There is **no** rule for the forgeable-`X-Forwarded-For` antipattern, and
**no** rule for a missing per-account limit, in any tier.

```bash
bandit -r labs/post_11_brute_force/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_11_brute_force/
semgrep scan --config r/python.django --config r/python labs/post_11_brute_force/
```

## Why there is no custom rule (and no CI scan-assert)

The two vulnerable properties are both things a syntactic scanner cannot assert:

1. **The wrong key.** The vulnerable view rate-limits on `X-Forwarded-For[0]`, a
   client-controlled value; the secure view keys the counter on the **account**.
   Whether a limiter is keyed on the right thing is a *semantic* judgement about
   what the value means and who controls it — not a matchable sink. (A narrow
   rule could flag `X-Forwarded-For.split(",")[0]`, but that is one contributing
   detail, and the secure view has no contrasting XFF call to stay silent on, so
   there is no clean fires-vulnerable / silent-secure assert.)
2. **An absent control.** "No per-account counter" is the *absence* of code.
   There is nothing to match. A custom rule can flag a dangerous call; it cannot
   flag a missing one.

This is what separates Lab 11 from IDOR (Post 6) and mass assignment (Posts 7, 10):
the standard tools **missed those too**, but a syntactic shape survived — an
owner-unscoped `.get()`, a `fields='__all__'` — so a custom rule could still fire
on the vulnerable view and stay silent on the secure one. Here the views differ only
by a call to this lab's own helper, so the "miss" is **unruleable**, not "write a rule."

So Lab 11 ships **no custom rule** and carries **no SAST scan-assert** — its gate
is `tests.py` (the universal gate). The automatable signal is **dynamic**: the
`curl` loop in the README rotates a forged `X-Forwarded-For` and watches the
IP-keyed limit fail to trigger, then shows the per-account lockout holding
regardless of source. That is the honest CySA+ lesson here — some findings come
from a threat-model review and a dynamic probe, not from any scanner.

## Why there is no captured DAST run, either

Brute force is the weakest DAST candidate in the series, for three reasons:

1. **No signature to read.** DAST tools like sqlmap fire a crafted payload and
   read a fingerprint in the *response*. Brute force leaves none — its symptom
   is behaviour across many requests, not something in one response.
2. **You cannot safely probe for an absence.** Testing a *declared* policy is
   bounded (WSTG-ATHN-03: a few failures, then the correct password — what
   `tests.py` does), but a scanner that knows no policy could only be *sure* a
   limit is missing by hammering the endpoint until it blocks or falls over — a
   denial-of-service. OWASP ZAP's active scan has no rule for a missing rate limit.
3. **A generic tool gets this lab backwards.** Point Hydra or a ZAP fuzzer at
   `vulnerable/login/` *without* rotating the header and it is blocked after five
   tries and finds no password, so the run reads as **protected** — a false negative.
   The bypass only appears to a probe that already knows to forge and rotate
   `X-Forwarded-For`, which is threat-model knowledge, not a scanner's rule set.

So the dynamic signal is the `curl` XFF-rotation loop in the lab README (and
`tests.py`, which runs the same attack deterministically through the Django test
client). A scripted credential-stuffing run (Hydra, Patator, a ZAP fuzzing loop)
with the same rotation would show the same effect; none is captured here, because
`tests.py` is the deterministic version of it.

`django-axes` is the production control the post recommends; a linter/scanner
still would not *find* the missing lockout for you — you have to know to add it.
