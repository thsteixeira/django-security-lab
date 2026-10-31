# Scan evidence — Lab 18 (Weak Password Hashing)

Captured 2026-10-31. Bandit 1.9.4, Semgrep 1.170.0 (the CI pins).
Every command below is reproducible from a clone. The scans were captured in a
`python:3.13-slim` container with the repository mounted read-only, so the paths
they print are already relative to the repo root.

| File | Tool | Headline |
|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | **fires on the vulnerable view, for the name** — `B324` on `views_vulnerable.py:45`, and on every other `hashlib.sha1` call in the module, the fix's wrapped hasher included; nothing on `views_secure.py` |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 | **the same, plus a false positive on the fix** — curated 8/156 (`insecure-hash-algorithm-sha1` ×7, and `use-none-for-password-default` on the *secure* view), registry 19/372; no rule in the five configs looks at where a password digest is stored |
| [`fast-hash-variants.txt`](fast-hash-variants.txt) | both | **the name is all they see** — the same line with `sha256`, `sha3_256` or `blake2b` draws nothing from either tool, and `usedforsecurity=False` silences Bandit |
| [`semgrep-custom-rule.txt`](semgrep-custom-rule.txt) | Semgrep 1.170.0 | the custom rule [`rules/password_hashing.yaml`](../../../rules/password_hashing.yaml) passes its fixture, **fires on `views_vulnerable.py:45`** (and the `SHA1Backend` comparison) and is **silent on `views_secure.py`** and on the wrapped hasher |

## What the standard tools say

```bash
bandit -r labs/post_18_password_hashing/
# 9 issues: B324 x7 (every hashlib.sha1 call), B105 x2
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_18_password_hashing/
# Ran 156 rules on 21 files: 8 findings.
semgrep scan --config r/python.django --config r/python labs/post_18_password_hashing/
# Ran 372 rules on 21 files: 19 findings.
```

| Tool / rule | Where | Relevant? |
|---|---|---|
| Bandit `B324`, Semgrep `insecure-hash-algorithm-sha1` | `views_vulnerable.py` L45 | the defect, so a hit — but for the algorithm's name; see below |
| the same two | `backends.py` L24 | the same mistake's login half: `SHA1Backend` compares a bare SHA-1 |
| the same two | `hashers.py` L28 | no — the **fix**. `PBKDF2WrappedSHA1PasswordHasher` must SHA-1 the password to reach the old digest it wraps in PBKDF2 (Django's documented recipe). The tools cannot tell it from the bug |
| the same two | `seed.py` L44, `tests.py` L63, `crack.py` L75 and L86 | no — the legacy seed, a test that recomputes the digest, and the attacker's cracker |
| Semgrep `use-none-for-password-default` (ERROR) | `views_secure.py` L27 | no — a false positive, on the **fix**. The rule flags `request.POST.get("password", "")` reaching `set_password()`, which could set an empty password, but line 29 refuses an empty one with a 400 first. It is the highest-severity finding of the run |
| Semgrep `unvalidated-password` (registry only) | `views_secure.py` L35, `tests.py` L165 | not this lab's class: the secure sign-up deliberately validates nothing, because password strength is Lab 13 |
| Semgrep `no-csrf-exempt`, `direct-use-of-httpresponse` (registry only) | both views alike, the note page | no — the labs' CSRF-off (B1) and inline-HTML conventions, the same on both sides of the pair |
| Semgrep `use-defusedcsv`, `is-function-without-parentheses` (registry only) | the leak command, `views_note.py` L15 | no — CSV-formula injection in a command whose output nobody opens in a spreadsheet, and `request.user.is_authenticated`, a property since Django 1.10 |
| Bandit `B105` | `seed.py` L27, `crack.py` L103 | `LEGACY_PASSWORD = "october12"` is a fair hit on a lab constant; `"password": None` is a false positive on a dictionary key |

So, as built, the pair is told apart: the vulnerable line is flagged and the secure
sign-up is not. The series' decision table asks one more question before that counts
as a pass: did the tool catch it **for the right reason**
(`SECURITY_BLOG_SERIES_PLAN.md` §6.4.1)?

## Why: the rules match the algorithm's name, not the stored digest

The defect is not SHA-1. It is a fast, unsalted digest written into
`User.password`, and SHA-256 is just as fast. Both standard checks are blocklists of
algorithm names:

- **Bandit's `B324`** reports `hashlib.md5`, `hashlib.sha1` and `hashlib.new()` with
  those names, unless the call passes `usedforsecurity=False`
  ([plugin docs](https://bandit.readthedocs.io/en/1.9.4/plugins/b324_hashlib.html)).
- **Semgrep's `insecure-hash-algorithm-sha1`** is the single pattern
  `hashlib.sha1(...)`. Its message is about signatures — "SHA1 is not collision
  resistant and is therefore not suitable as a cryptographic signature" — its ASVS
  tag is 4.0's V6.2.2, and its autofix rewrites `sha1` to `sha256`
  ([rule](https://semgrep.dev/r/python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1)).
  Collision resistance is what ASVS 5.0 asks of hashes in signatures and integrity
  checks (V11.4.3). Password storage is a different requirement (V11.4.2): a
  computationally intensive key derivation function.

`fast-hash-variants.txt` checks the consequence. Four one-line edits of the
vulnerable view, each as crackable as the original:

```bash
sed 's/hashlib\.sha1(password\.encode())/hashlib.sha256(password.encode())/' \
    labs/post_18_password_hashing/views_vulnerable.py > /tmp/v/sha256.py
# ... and the same for sha3_256, blake2b, and sha1(..., usedforsecurity=False)
```

| Line 45 stores | Bandit | Semgrep, all five configs |
|---|---|---|
| `hashlib.sha1(...)` (the lab) | `B324` | `insecure-hash-algorithm-sha1` |
| `hashlib.sha256(...)` | nothing | nothing |
| `hashlib.sha3_256(...)` | nothing | nothing |
| `hashlib.blake2b(...)` | nothing | nothing |
| `hashlib.sha1(..., usedforsecurity=False)` | nothing | `insecure-hash-algorithm-sha1` |

Applying the Semgrep rule's own autofix leaves the vulnerability in place and
silences every scanner the series runs. Following Bandit's suggestion silences
Bandit.

And nothing else in the rule sets looks at where the digest goes. Grepping the rule
definitions of all five configs (the script is printed at the end of
`semgrep.txt`):

```
p/django: 28 rules; storage terms: 0; set_password: ['password-empty-string', 'use-none-for-password-default']
p/python: 151 rules; storage terms: 0; set_password: ['password-empty-string', 'use-none-for-password-default']
p/owasp-top-ten: 559 rules; storage terms: 0; set_password: ['password-empty-string', 'use-none-for-password-default']
r/python.django: 79 rules; storage terms: 0; set_password: ['password-empty-string', 'unvalidated-password', 'use-none-for-password-default']
r/python: 378 rules; storage terms: 0; set_password: ['password-empty-string', 'unvalidated-password', 'use-none-for-password-default']
```

No rule mentions `.password =`, `make_password`, `PASSWORD_HASHERS`, a
`PasswordHasher` or `check_password`. The three that mention `set_password` all
examine the fix's call: an empty default, a missing strength check. In Bandit 1.9.4
(`bandit -h`), the password checks `B105`–`B107` look for hard-coded passwords and
the three Django checks for `extra()`, `RawSQL` and `mark_safe()`: none looks at how
a password is stored.

That is the "they miss it" outcome in the decision table: the class — a password
stored as a fast digest — has no rule, and the lab's line is caught only because it
happens to say `sha1`.

## The custom rule

[`rules/password_hashing.yaml`](../../../rules/password_hashing.yaml) is a **taint**
rule. Its sources are hashlib's digest constructors (any algorithm, and
`hashlib.new`) and `hmac`. Its sinks are the places a password value is written or
compared: an assignment to `.password`, a `password=` keyword in a model's
constructor (`User(...)`), its `create()` or a queryset's `update()`, and an
equality test against `.password`. `make_password()` and a hasher's `encode()`
sanitise, because a digest wrapped in PBKDF2 is the documented upgrade path. The
hasher is recognised by name — `get_hasher(...)`, or a receiver whose name ends in
`hasher` — so `digest.encode("ascii", "strict")`, an ordinary string method with
two arguments, does not clear the taint (a fixture `ruleid` line holds that). Taint, because the digest often goes through
a local first (`digest = hashlib.sha256(...).hexdigest()`).

```bash
semgrep --test --config rules/password_hashing.yaml rules/password_hashing.py
# 1/1: ✓ All tests passed
semgrep scan --config rules/password_hashing.yaml labs/post_18_password_hashing/views_vulnerable.py
# Ran 1 rule on 1 file: 1 finding.       (line 45)
semgrep scan --config rules/password_hashing.yaml labs/post_18_password_hashing/views_secure.py
# Ran 1 rule on 1 file: 0 findings.
semgrep scan --config rules/password_hashing.yaml labs/
# Ran 1 rule on 218 files: 3 findings.   (views_vulnerable.py:45, backends.py:24, seed.py:44)
```

It fires on `backends.py:24` too, the `SHA1Backend` comparison the hand-hashed
column forces, and on `seed.py:44`, which writes the legacy rows exactly as the
vulnerable view does. It is silent on `hashers.py` and `wrap.py`, the fix that both
standard tools flag, and on the attacker's `crack.py`, which hashes guesses but
stores nothing. It flags line 45 in all four variants above.

**What it flags on purpose:** HMAC with the `SECRET_KEY` as a pepper, and a salt
added by hand. The first is still one fast hash per guess; the second makes the
attack per row, but each guess is still one fast hash.

**What it misses** (marked `todoruleid` in [`rules/password_hashing.py`](../../../rules/password_hashing.py)):
a field with another name (`password_hash`); a raw SQL `UPDATE`; a fast scheme from
a third-party library (passlib's `md5_crypt`); and `hashlib.pbkdf2_hmac()` with one
iteration and a fixed salt, excluded because the same call with sound settings is a
slow KDF. Choosing a weaker hasher in settings — `MD5PasswordHasher` first in
`PASSWORD_HASHERS`, a subclass with lowered iterations — is configuration, not
dataflow, and no rule here sees it.

**What it flags although it is harmless** (marked `todook`): a model field named
`password` holding the SHA-256 of a long random token, such as an API key. A fast
hash is enough when nobody can guess the input, but the rule cannot see where the
hashed value came from.

`semgrep --test` does not check `todo` lines, so a JSON scan of the fixture confirms
them: it flags lines 23, 36, 48, 53, 59, 64, 70, 77, 82, 87, 92 and 99 (the twelve
`ruleid` lines) and 165 (the `todook` line), and none of the four `todoruleid` lines
(140, 147, 152, 158).

CI asserts the split in the hermetic custom-rules job.
