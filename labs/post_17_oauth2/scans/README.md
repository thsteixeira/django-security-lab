# Scan evidence — Lab 17 (OAuth2 Misimplementation)

Captured 2026-10-30. Bandit 1.9.4, Semgrep 1.170.0 (the CI pins).
Every command below is reproducible from a clone. The scans were captured in a
`python:3.13-slim` container with the repository mounted read-only, so the paths
they print are already relative to the repo root; the rule-pack grep ran on the
host, as `semgrep.txt`'s header says.

| File | Tool | Headline |
|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | **nothing in either view** — 2 `B105` hits in `provider.py`: the committed client secret, and the key `"token_type"` beside `"Bearer"` |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 | **no tier tells the pair apart** — curated 2/156 and registry 7/372, all in `provider.py` or on both callbacks alike; no rule in the five configs mentions an identity claim |
| [`semgrep-custom-rule.txt`](semgrep-custom-rule.txt) | Semgrep 1.170.0 | the custom rule [`rules/oauth2.yaml`](../../../rules/oauth2.yaml) passes its fixture, **fires on `views_vulnerable.py:46`** and is **silent on `views_secure.py`** |

## What the standard tools say

```bash
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_17_oauth2/
# Ran 156 rules on 18 files: 2 findings.
semgrep scan --config r/python.django --config r/python labs/post_17_oauth2/
# Ran 372 rules on 18 files: 7 findings.
bandit -r labs/post_17_oauth2/
# 2 issues, both B105 in provider.py
```

| Tool / rule | Where | Relevant? |
|---|---|---|
| Semgrep `open-redirect` | `provider.py` L67 (the authorize view) | no — a false positive. The view refuses any `redirect_uri` that is not in an exact allowlist before it redirects, but the rule is a syntactic pattern whose only exemptions are a call to `is_safe_url()` or `url_has_allowed_host_and_scheme()` in the same function, so a membership check does not count |
| Semgrep `jwt-python-hardcoded-secret` | `provider.py` L118 | fair, and intended: the in-lab provider signs ID tokens with a client secret committed to the repo, which is never deployed |
| Semgrep `direct-use-of-httpresponse` (registry only) | both callbacks (`views_vulnerable.py` L50, `views_secure.py` L47), `views_connect.py` L50 and L59, `provider.py` L99 | no — the labs' inline-HTML convention (Lab 02's class), the same on both sides of the pair |
| Bandit `B105` | `provider.py` L44 | the committed client secret — fair, as above |
| Bandit `B105` | `provider.py` L133 | no — `"token_type": "Bearer"`: B105 matches the word `token` in a dictionary key and reports the constant beside it |

The line that matters, `views_vulnerable.py:46`,

```python
user = User.objects.filter(email__iexact=claims["email"]).first()
```

draws nothing from any of them, and neither does its fix on `views_secure.py`.

## Why: nothing in the rule sets is about identity claims

The defect is not a dangerous call. It is an ordinary ORM lookup whose value happens
to come from the `email` claim of an ID token that was verified correctly, and a rule
would have to know that this claim, among all the token's claims, must not identify a
person. Grepping the rule definitions of all five configs for the terms a rule about
this would most likely use:

```bash
for c in p/django p/python p/owasp-top-ten r/python.django r/python; do
  curl -sL "https://semgrep.dev/c/$c" | grep -ciE 'email_verified|\["email"\]|email__iexact|preferred_username|allauth|social_core|associate_by_email|EMAIL_AUTHENTICATION|id_token|uid_field'
done
# 0
# 0
# 0
# 0
# 0
```

Zero in each (28, 151, 559, 79 and 378 rule definitions respectively, on the
capture date). Bandit 1.9.4 ships 75 checks, and a case-insensitive grep of its
plugins for `email`, `oauth` or `id_token` finds one match, the SNMP check's
`noAuthNoPriv`: nothing that could see this lookup.

That is the "no rule in any tier" outcome in the series' decision table
(`SECURITY_BLOG_SERIES_PLAN.md` §6.4.1), which is when this repo writes a rule.

## The custom rule

[`rules/oauth2.yaml`](../../../rules/oauth2.yaml) is a **taint** rule. Its sources
are the calls that produce verified claims — `jwt.decode(...)` and a
`verify_id_token(...)` helper — and its sink is an account lookup (`filter`, `get`,
`get_or_create`, `update_or_create`, `exclude`) whose keyword is the email field
(`email`, `email__exact`, `email__iexact`). Taint, because the claim usually travels
through a local first (`claims = ...`, `address = claims.get("email")`).

```bash
semgrep --test --config rules/oauth2.yaml rules/oauth2.py
# 1/1: ✓ All tests passed
semgrep scan --config rules/oauth2.yaml labs/post_17_oauth2/views_vulnerable.py
# Ran 1 rule on 1 file: 1 finding.       (line 46)
semgrep scan --config rules/oauth2.yaml labs/post_17_oauth2/views_secure.py
# Ran 1 rule on 1 file: 0 findings.
```

The whole claims dictionary is tainted, so the sink is narrowed to the email keyword:
the secure lookup, `Identity.objects.filter(issuer=claims["iss"], subject=claims["sub"])`,
stays silent, and so does `create_user(..., email=claims["email"])`, which writes a new
account rather than finding an existing one. An email typed into a form
(`request.POST["email"]`, as in a password-reset view) is not a source, so the rule
leaves it alone.

**What it flags on purpose:** a lookup behind an `if claims.get("email_verified"):`
check. `email_verified` is a claim about someone else's verification, and the
identifier is still a reassignable address.

**What it misses** (marked `todoruleid` in [`rules/oauth2.py`](../../../rules/oauth2.py)):
a lookup keyed on a username claim (`username=claims["preferred_username"]`), which is
the same mistake outside the rule's email scope; claims fetched from a userinfo
endpoint (`requests.get(...).json()["email"]`), which is not a source the rule knows;
the email inside a `Q()` object or an `email__in` list; and a lookup through a queryset
held in a variable (`users = User.objects.all()`, then `users.filter(...)`), which is
not the `$MODEL.objects...` shape the sink matches.

**What it flags although it is harmless** (marked `todook`): a sign-up check that only
asks whether the address is taken (`.filter(email__iexact=...).exists()`), and a lookup
pinned to the signed-in user's own `pk`. The sink is any email-keyed lookup, not one
whose result is logged in, so the rule reports where the claim meets the query and
leaves the rest to the reviewer.

`semgrep --test` does not check `todo` lines, so a JSON scan of the fixture confirms
them: it flags lines 20, 35, 42 and 52 (the four `ruleid` lines) and 111 and 118 (the
two `todook` lines), and none of the five `todoruleid` lines (72, 81, 88, 95, 103).

**What it cannot see at all:** the same mistake made in settings rather than code —
django-allauth's `SOCIALACCOUNT_EMAIL_AUTHENTICATION` with `VERIFIED_EMAIL`, an
OpenID Connect `uid_field` changed from `sub`, or social-auth's `associate_by_email`
in the pipeline. Those are a `grep` of the settings, not a dataflow.

CI asserts the split in the hermetic custom-rules job.
