# Scan evidence — Lab 16 (JWT Attacks)

Captured 2026-10-24. Bandit 1.9.4, Semgrep 1.170.0.
Every command below is reproducible from a clone. The files were captured on
Windows; the path separators they printed are normalised, as each file's header
says.

| File | Tool | Headline |
|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | **nothing in any view** — Bandit has no JWT check; 2 false positives in `tests.py`; on the settings it reports the fix's `"CHECK_REVOKE_TOKEN": True` as a hard-coded password |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 | the curated packs **catch the bug**: `unverified-jwt-decode` fires on `views_vulnerable.py:35` and the secure view draws nothing; audit tier 5/372, nothing new about tokens; `config/settings.py` 0/377 |

**No custom rule.** The curated packs already tell the bug from the fix, which is
the case in which this repo writes none (see [CONTRIBUTING.md](../../../CONTRIBUTING.md),
"The custom-rule exception") — the same outcome as Lab 01 (SQLi) and Lab 04
(command injection). CI asserts the split in the SAST job.

## Semgrep, curated tier: the bug, and the attacker's own helper

```bash
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_16_jwt/
# Ran 156 rules on 16 files: 2 findings.
```

| Rule | Where | Relevant? |
|---|---|---|
| `unverified-jwt-decode` | `views_vulnerable.py` L35 | **yes — the bug**: `jwt.decode(token, options={"verify_signature": False})` |
| `jwt-python-none-alg` | `tests.py` L49 | correct, and intended: `unsigned_token()` is the test's forging helper, which builds an `alg: none` token on purpose |

`views_secure.py` draws nothing, because it decodes nothing itself.

The curated packs split the pair here and in none of Labs 11–15, and the reason is
in the rule. Its whole definition is public:

```bash
curl -sL https://semgrep.dev/c/r/python.jwt.security.unverified-jwt-decode.unverified-jwt-decode
```

It matches `jwt.decode(..., options={..., "verify_signature": False, ...}, ...)`, or
the same dictionary assigned to a variable first and passed as `options=`. The bug
is a literal in the source, and a rule can match a literal. That pattern is also
its limit. Semgrep resolves imports, so `import jwt as tokenlib` or
`from jwt import decode` does not hide the call
([pattern syntax, "Imports"](https://semgrep.dev/docs/writing-rules/pattern-syntax#imports));
but the pattern is a dictionary literal, so options built any other way
(`dict(verify_signature=False)`, or a key set after the dictionary is made) fall
outside it.

The rule ships an autofix that rewrites `False` to `True`. Applied to line 35 it
leaves `jwt.decode(token, options={"verify_signature": True})`, a call with no key
and no `algorithms`, which PyJWT 2.15.1 refuses:

```bash
docker compose run --rm web python -c "
import jwt
token = jwt.encode({'user_id': '2'}, None, algorithm='none')
jwt.decode(token, options={'verify_signature': True})
"
# jwt.exceptions.DecodeError: It is required that you pass in a value for the "algorithms" argument when calling decode().
```

That is the same error that sends a developer looking for `verify_signature: False`
in the first place. The autofix fails closed, which is better than open, but it is
not the fix: the fix is to stop decoding by hand (`views_secure.py`).

## Semgrep, audit/registry tier: 5 findings, nothing new about tokens

```bash
semgrep scan --config r/python.django --config r/python labs/post_16_jwt/
# Ran 372 rules on 16 files: 5 findings.
```

| Rule | Where | Relevant? |
|---|---|---|
| `unverified-jwt-decode` | `views_vulnerable.py` L35 | yes — the same finding |
| `jwt-python-none-alg` | `tests.py` L49 | the test's forging helper, as above |
| `direct-use-of-httpresponse` | `exports.py` L16, L20 | no — the labs build HTML inline (Lab 02's class), and both views share this helper, so it says nothing about the pair |
| `unvalidated-password` | `tests.py` L139 | no — a fixture `set_password()` (Lab 13's class) |

## The settings: invisible to Semgrep, misread by Bandit

Half of this lab's lesson is not in a view at all. It is the `SIMPLE_JWT` block in
`config/settings.py`: its own signing key instead of `SECRET_KEY`, five-minute
access tokens, refresh rotation with the blacklist, and `CHECK_REVOKE_TOKEN`.

```bash
semgrep scan --config p/django --config p/python --config p/owasp-top-ten \
             --config r/python.django --config r/python config/settings.py
# Ran 377 rules on 1 file: 0 findings.
```

Zero, and not because the block is correct: no rule in any of the five packs reads
a `SIMPLE_JWT` block. Grepping the rule definitions themselves:

```bash
for c in p/django p/python p/owasp-top-ten r/python.django r/python; do
  curl -sL "https://semgrep.dev/c/$c" | grep -cE 'SIMPLE_JWT|simplejwt|CHECK_REVOKE_TOKEN|SIGNING_KEY'
done
# 0
# 0
# 0
# 0
# 0
```

Bandit does look at the settings, and gets the two keys the wrong way round:

```bash
bandit config/settings.py
# >> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'django-security-lab-not-a-secret-never-deploy-this'
#    Location: config/settings.py:20:13
# >> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'True'
#    Location: config/settings.py:115:4
```

The first is a fair hit: `SECRET_KEY` is committed, and it is the key simplejwt
signs with when `SIGNING_KEY` is not set. The second is line 115,
`"CHECK_REVOKE_TOKEN": True` — the setting that revokes tokens on a password change,
reported as a leaked credential. `B105` matches a name against
`pas+wo?r?d|pass(phrase)?|pwd|token|secrete?` at a word edge (`_token` at the end
counts) and reports whatever constant sits beside a matching dictionary key, `True`
included. `ROTATE_REFRESH_TOKENS` escapes on its trailing S.

## Bandit on the lab: no JWT check exists

```bash
bandit -r labs/post_16_jwt/
# >> Issue: [B105:hardcoded_password_string] Possible hardcoded password: '/jwt/token/'
#    Location: labs/post_16_jwt/tests.py:42:8
# >> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'access'
#    Location: labs/post_16_jwt/tests.py:115:12
```

Both are `B105` on names: a URL constant called `TOKEN`, and the dictionary key
`"token_type"`. Nothing in any view. Bandit 1.9.4 has no check that mentions JWT —
its 75 tests and the installed package itself contain no reference to it — so the
unverified decode on line 35 is outside what it looks for.

## What no scanner here sees

The logout window, the revocation on a password change, and the key separation are
behaviour and configuration, not a line to match. `tests.py` asserts them instead:
`test_password_change_revokes_access_tokens`, `test_the_project_signs_with_its_own_key`,
`test_access_tokens_live_five_minutes_at_most`, the simplejwt defaults this project
replaces, and `test_logout_ends_the_access_token`, kept as an expected failure
because no setting closes that window.
