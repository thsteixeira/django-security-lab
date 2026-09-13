# Lab 13 — Weak Passwords & Validators

Companion lab for the blog post
**[Weak Passwords and Validators](https://thiagoteixeira.tech/blog/)** *(link finalised on publication)*.

| | |
|---|---|
| **OWASP** | A07:2025 — Authentication Failures |
| **CWE** | CWE-521 — Weak Password Requirements · CWE-1391 — Use of Weak Credentials |
| **ASVS** | V2.1.1 — passwords of at least 12 characters · V2.1.7 — verified against a breached-password set |
| **NIST** | SP 800-63B-4 §3.1.1.2 — 15-character minimum (single factor), **SHALL NOT** impose composition rules, **SHALL** compare against a blocklist |
| **Detection** | Semgrep's **audit tier** carries `python.django.security.audit.unvalidated-password`: it fires on the bare `set_password()` and is silent on the inline fix, so **no custom rule** is needed. The curated `p/django` pack excludes it (`subcategory: audit`). It also false-positives on the Form-based view, and its published autofix is broken. Bandit misses the class entirely. See [`scans/`](scans/) |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The three views

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | `user.set_password(pw)` — hashes the password correctly and **never validates it**. Nothing in this path calls `validate_password()`, and nothing would save it if it did: this project deliberately runs on Django's real default, `AUTH_PASSWORD_VALIDATORS = []` (see below), so the policy the secure views enforce is the one they pass explicitly |
| Secure | [`views_secure.py`](views_secure.py) | the same flow with `validate_password(password, user)` **before** the write, and the `ValidationError` surfaced to the caller |
| Secure (idiomatic) | [`views_form.py`](views_form.py) | the shape most real Django apps use — a `Form` validates in `clean_password()`, the view writes only after `is_valid()`. Equally correct, and the one Semgrep **false-positives** on (see [`scans/README.md`](scans/README.md)) |

All three register a user and hash the password with `set_password()`. The only
difference is whether anything calls `validate_password()` first — and *where*.
Both qualifiers are load-bearing: validating **after** `set_password()` raises the
exception once the weak password is already committed, and calling
`validate_password(password)` **without the user** silently disables
`UserAttributeSimilarityValidator`, whose `validate()` opens with
`if not user: return`.

The privilege boundary is a fourth endpoint, [`/passwords/secret/`](views_account.py),
which serves **carol's** private data (the flag) only to a session authenticated
as carol. **Guessing her password in one attempt *is* the exploit.**

## Why `Password123!`

The seeded victim's password is not an invention:

- It satisfies **every** character-class rule anyone has ever written — uppercase, lowercase, digit, symbol.
- It passes **all four** of Django's default validators (asserted in `tests.py`, so a future Django release that enlarges `common-passwords.txt.gz` turns the test red rather than quietly making the lab wrong).
- It has been seen **295,389 times** in the Have I Been Pwned corpus.

That is the entire argument for why composition rules do not measure what people
think they measure — and why NIST now forbids them.

## The password policy — scoped to this lab, not to the project

This lab needs a real policy to enforce. It does **not** put one in
`config/settings.py`, because `AUTH_PASSWORD_VALIDATORS` is a **global** setting
and that would have applied this lab's 15-character floor to every other lab in
the repo. The collision is not hypothetical: the shared B7 cast password
`labpass` is 7 characters and Lab 11's `summer2024` is 10, so both would be
rejected by any future lab built on Django's auth *forms* — `SetPasswordForm`,
`UserCreationForm`, `PasswordChangeForm`, all of which validate via
`SetPasswordMixin`. Lab 14 (Password Reset) is form-based by design and would
have been the first casualty.

So the policy lives in [`policy.py`](policy.py), and the validating views pass it
explicitly:

```python
validate_password(password, user, password_validators=get_policy())
```

`validate_password()`'s third parameter exists for exactly this. The config
format is byte-identical to an `AUTH_PASSWORD_VALIDATORS` block, so what is in
`policy.py` is what you would paste into `settings.py` in a real project — shaped
to NIST SP 800-63B-4 rather than to habit: a **15-character** floor, **no
composition rules**, and a **blocklist** (Django's shipped 19,640-entry list plus
[`BreachListValidator`](validators.py) reading a committed gzipped file of the
composition-rule survivors and the site-specific terms no generic wordlist carries).

There is a happy side effect. Because nothing sets it, this project runs on
Django's genuine default:

```python
# django/conf/global_settings.py
AUTH_PASSWORD_VALIDATORS = []
```

The four-validator block everyone recognises comes from the `startproject`
*template*, not from the framework. That is the blog post's opening claim, and it
is now true of this repo rather than merely described by it —
`tests.py::test_the_policy_is_scoped_to_this_lab` asserts both halves: the
project setting is empty, and the lab's own policy still refuses `labpass`.

[`validators.py`](validators.py) also ships **`PwnedPasswordValidator`**, the live
k-anonymity version that queries the HIBP range API (only the first 5 hex
characters of the SHA-1 leave the process). It is deliberately **not** in the
active policy, for two reasons. A suite that depends on a third party's uptime goes
red for reasons that have nothing to do with the code — and, more decisively, the
`web` container in [`docker-compose.yml`](../../docker-compose.yml) sits on an
`internal: true` network with **no egress at all** (B6 tier-3 containment), so a
validator that calls out to the internet could not work here even if it were
wired in. `tests.py` exercises it against a stubbed transport instead, covering
the SHA-1 split, the suffix comparison, the threshold and both fail-open and
fail-closed branches — everything except the socket.

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
docker compose exec web python manage.py seed_labs
```

The seed creates **carol** (the victim) with `Password123!` — written exactly the
way the vulnerable view writes it — and gives her a private secret holding the
flag. Everything below is `curl` against that stack; no browser needed. On Windows
PowerShell, `curl` is an alias for `Invoke-WebRequest`; use `curl.exe`, or Git Bash.

## Exploit the pair from the command line

**1. The VULNERABLE registration accepts a password the project's policy forbids.**
`set_password()` hashes it and stores it; nothing consults `AUTH_PASSWORD_VALIDATORS`:

```bash
curl -s -d 'username=mallory&password=Password123!' \
     http://127.0.0.1:8000/passwords/vulnerable/register/
# registered mallory (password NOT validated)      [HTTP 201]
```

**2. The SECURE registration refuses the same password** — and says why. Note that
neither reason is a composition rule:

```bash
curl -s -d 'username=mallory2&password=Password123!' \
     http://127.0.0.1:8000/passwords/secure/register/
# password rejected:
#   - This password is too short. It must contain at least 15 characters.
#   - This password has appeared in a known data breach and cannot be used.
#                                                  [HTTP 400]
```

**3. It accepts a passphrase.** Longer, no uppercase, no digit, no symbol —
and not in any blocklist:

```bash
curl -s --data-urlencode 'username=mallory3' \
        --data-urlencode 'password=flat marble kettle horizon' \
     http://127.0.0.1:8000/passwords/secure/register/
# registered mallory3 (password validated)         [HTTP 201]
```

**4. The impact — one guess.** `carol` was registered the way step 1 registers
people. There is no wordlist walk here and no throttle to defeat: `Password123!`
sits near the top of every real corpus, so the first attempt lands:

```bash
curl -s -c atk.txt -d 'username=carol&password=Password123!' \
     http://127.0.0.1:8000/accounts/login/
# logged in as carol                               [HTTP 200]
```

**5. Capture the flag** — carol's private secret, from carol's session:

```bash
curl -s -b atk.txt http://127.0.0.1:8000/passwords/secret/
# <h1>Private secret</h1><p>carol: private: FLAG{one_guess_the_validator_never_ran}</p>
```

**6. The idiomatic fix refuses it too**, with the validation living in a `Form`:

```bash
curl -s -d 'username=mallory4&password=Password123!' \
     http://127.0.0.1:8000/passwords/form/register/
# password rejected:
#   - This password is too short. It must contain at least 15 characters.
#   - This password has appeared in a known data breach and cannot be used.
#                                                  [HTTP 400]
```

Steps 1–3 and 6 create users, so re-running them returns `HTTP 409 username taken`.
Pick fresh usernames, or reset the stack with
`docker compose down -v && docker compose up -d`.

Or prove all of it in one command (from the repo root):

```bash
docker compose run --rm web python manage.py test labs.post_13_weak_passwords
# Ran 18 tests in 2.288s
# OK
```

## Isolation

This lab teaches weak-password acceptance and nothing else. There is **no
throttle to defeat** — the attacker gets the account in one guess because the
password is cheap, not because the guessing is fast; rate limiting and lockout are
Lab 11, and the two labs deliberately use different victim accounts (`carol` here,
`victim` there) because both seeds run in the same `seed_labs` pass. Hashing is
Lab 18: `set_password()` here is entirely correct, which is exactly what makes the
missing validation easy to miss. The secret lookup is scoped to `request.user`, so
it does not drift into IDOR (Lab 6), and output is escaped (Lab 2). Global CSRF is
off in this project, so the registration POST needs no token (Lab 8).

## Scanning it

**Bandit misses this class completely.** It walks the Python AST for `B`-numbered
risky *constructs*, and the defect here is not a construct — it is the **absence of
a call** beside an entirely correct one. `set_password()` is the right function,
used correctly. Its four findings are all on lab fixtures or on the *secure*
validator.

**Semgrep's curated packs miss it too** (`p/django`, `p/python`,
`p/owasp-top-ten` — 3 findings, none about password validation, and the two that
touch the views fire on the vulnerable and the secure one alike).

**The audit tier catches it:**

```bash
semgrep scan --config r/python.django --config r/python labs/post_13_weak_passwords/
# ❯❱ python.django.security.audit.unvalidated-password
#    labs/post_13_weak_passwords/views_vulnerable.py:37
```

It fires on the vulnerable view and is **silent on `views_secure.py`**, so this lab
ships **no custom rule** (§6.4.1) — the finding is *"the curated packs exclude it;
run the audit tier"*, the same shape as Lab 08.

Two caveats, both verified and both written up in [`scans/README.md`](scans/README.md):
the rule **false-positives on [`views_form.py`](views_form.py)** because it only
looks for `validate_password()` in the same lexical scope, and its **published
autofix is broken** — `validate_password()` returns `None` on success, so
`if validate_password(...): set_password(...)` never sets the password at all.
