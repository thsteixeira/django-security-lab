"""The attacker's side of Lab 18: crack a leaked password table, offline.

Standard library only — this runs on the attacker's machine, not in the app, and
nothing the application does (rate limits, lockout, logging) can see it. Reads the
CSV that ``manage.py dump_password_table`` prints, from a file or from ``-``
(stdin), and guesses from a wordlist: Django's own 19,640-entry
``common-passwords.txt.gz`` by default, the list ``CommonPasswordValidator`` uses.

    python labs/post_18_password_hashing/crack.py leak.csv
    python labs/post_18_password_hashing/crack.py leak.csv --user elisa --budget 10

Unsalted SHA-1 rows are cracked together in one pass: each guess is hashed once
and looked up among every leaked digest, which is the loop the post walks
through. Salted PBKDF2 rows (``pbkdf2_sha256``, and ``pbkdf2_wrapped_sha1`` after
the wrap migration) cost a full PBKDF2 run per guess *per row*, so they are only
attempted for the accounts named with ``--user``, each within ``--budget`` seconds,
and the report says how long the whole list would take for that one account.
"""

import argparse
import base64
import csv
import gzip
import hashlib
import hmac
import re
import sys
import time
from pathlib import Path

SHA1_HEX = re.compile(r"^[0-9a-f]{40}$")
SALTED = ("pbkdf2_sha256", "pbkdf2_wrapped_sha1")


def default_wordlist():
    import django

    return Path(django.__file__).parent / "contrib" / "auth" / "common-passwords.txt.gz"


def read_wordlist(path):
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\r\n") for line in f]


def read_dump(stream):
    """[(username, stored password)] from the leak's CSV."""
    return [(row["username"], row["password"]) for row in csv.DictReader(stream)]


def kind(stored):
    if SHA1_HEX.match(stored):
        return "sha1"
    algorithm = stored.split("$", 1)[0]
    return algorithm if algorithm in SALTED else "other"


def crack_unsalted(rows, words):
    """One pass of the wordlist for every unsalted row at once.

    Returns ``{"found": {password: [usernames]}, "guesses": n, "seconds": s}``;
    ``guesses`` counts SHA-1 computations, which do not grow with the row count.
    """
    leaked = {}  # hash -> usernames
    for username, digest in rows:
        leaked.setdefault(digest, []).append(username)

    found, guesses, start = {}, 0, time.perf_counter()
    remaining = set(leaked)
    for guess in words:
        if not remaining:
            break
        guesses += 1
        digest = hashlib.sha1(guess.encode()).hexdigest()
        if digest in remaining:
            found[guess] = leaked[digest]
            remaining.discard(digest)
    return {"found": found, "guesses": guesses, "seconds": time.perf_counter() - start}


def pbkdf2_matches(stored, guess):
    algorithm, iterations, salt, expected = stored.split("$", 3)
    if algorithm == "pbkdf2_wrapped_sha1":
        # The wrapped row is PBKDF2 over the old digest, so a guess goes through both.
        guess = hashlib.sha1(guess.encode()).hexdigest()
    derived = hashlib.pbkdf2_hmac("sha256", guess.encode(), salt.encode(), int(iterations))
    return hmac.compare_digest(base64.b64encode(derived).decode("ascii"), expected)


def crack_salted(stored, words, budget=None):
    """Guess one salted row, giving up after ``budget`` seconds (``None``: no limit).

    Returns ``{"password": str | None, "guesses": n, "seconds": s}``.
    """
    guesses, start = 0, time.perf_counter()
    for guess in words:
        guesses += 1
        if pbkdf2_matches(stored, guess):
            return {"password": guess, "guesses": guesses, "seconds": time.perf_counter() - start}
        if budget is not None and time.perf_counter() - start >= budget:
            break
    return {"password": None, "guesses": guesses, "seconds": time.perf_counter() - start}


def duration(seconds):
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 120:
        return f"{seconds:.1f} s"
    if seconds < 7200:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Crack a leaked Django password table.")
    parser.add_argument("dump", help="CSV from dump_password_table, or - for stdin")
    parser.add_argument("--wordlist", help="default: Django's common-passwords.txt.gz")
    parser.add_argument("--user", action="append", default=[], help="attempt this salted row")
    parser.add_argument("--budget", type=float, default=10.0, help="seconds per salted row")
    args = parser.parse_args(argv)

    words = read_wordlist(args.wordlist or default_wordlist())
    if args.dump == "-":
        rows = read_dump(sys.stdin)
    else:
        with open(args.dump, newline="", encoding="utf-8") as f:
            rows = read_dump(f)

    unsalted = [r for r in rows if kind(r[1]) == "sha1"]
    salted = [r for r in rows if kind(r[1]) in SALTED]
    print(
        f"leak: {len(rows)} rows, {len(unsalted)} unsalted SHA-1 "
        f"({len({d for _, d in unsalted})} distinct), {len(salted)} salted PBKDF2, "
        f"{len(rows) - len(unsalted) - len(salted)} other; wordlist: {len(words):,} guesses"
    )

    if unsalted:
        result = crack_unsalted(unsalted, words)
        print(
            f"unsalted SHA-1: one pass for all {len(unsalted)} rows, "
            f"{result['guesses']:,} guesses in {duration(result['seconds'])}"
        )
        for password, usernames in result["found"].items():
            print(f"  {password}  {', '.join(usernames)}")

    targets = [r for r in salted if r[0] in args.user]
    if len(salted) > len(targets):
        print(
            f"salted PBKDF2: {len(salted) - len(targets)} rows not attempted; every "
            "guess is a full PBKDF2 run for one row (name rows with --user)"
        )
    for username, stored in targets:
        algorithm, iterations = stored.split("$")[:2]
        result = crack_salted(stored, words, budget=args.budget)
        label = f"  {username} ({algorithm}, {int(iterations):,} iterations)"
        if result["password"] is not None:
            print(f"{label}: {result['password']} after {result['guesses']:,} guesses, "
                  f"{duration(result['seconds'])}")
            continue
        rate = result["guesses"] / result["seconds"]
        print(
            f"{label}: not found in {duration(result['seconds'])} "
            f"({result['guesses']:,} guesses, {rate:.1f} a second); "
            f"the whole list would take about {duration(len(words) / rate)} "
            "for this one account"
        )


if __name__ == "__main__":
    main()
