"""Runnable proof that a leaked table of unsalted SHA-1 digests is cracked in one
offline pass, for every account at once — and that ``set_password()``, and the wrap
migration for the rows already stored, turn each guess into a PBKDF2 run per row.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_18_password_hashing

``test_the_leak_cracks_and_the_password_reads_carlas_note`` and
``test_a_secure_row_does_not_fall_to_the_same_attack`` are the pair that matters:
the same password and the same wordlist, cracked from one table in a fraction of
a second, and not reached in the other within the same attack.
"""

import hashlib
from io import StringIO

from django.conf import global_settings, settings
from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import Client, TestCase

from .crack import crack_salted, crack_unsalted, default_wordlist, kind, read_dump, read_wordlist
from .seed import FLAG, LEGACY_PASSWORD, seed

VULN_REGISTER = "/hashing/vulnerable/register/"
VULN_LOGIN = "/hashing/vulnerable/login/"
SECURE_REGISTER = "/hashing/secure/register/"
SECURE_LOGIN = "/accounts/login/"
NOTE = "/hashing/note/"

WORDS = read_wordlist(default_wordlist())
# 1-based position of the legacy password in Django's common-passwords list.
POSITION = WORDS.index(LEGACY_PASSWORD) + 1


def leak(usernames=None):
    """The table as the attacker gets it, optionally narrowed to some accounts."""
    out = StringIO()
    call_command("dump_password_table", stdout=out)
    out.seek(0)
    rows = read_dump(out)
    return [r for r in rows if usernames is None or r[0] in usernames]


class PasswordHashingLabTests(TestCase):
    def setUp(self):
        seed()

    def password_of(self, username):
        return User.objects.get(username=username).password

    def log_in(self, url, username, password):
        client = Client()
        return client, client.post(url, {"username": username, "password": password})

    # --- what the vulnerable sign-up writes ------------------------------------

    def test_vulnerable_register_stores_a_bare_unsalted_sha1(self):
        resp = Client().post(VULN_REGISTER, {"username": "mallory", "password": LEGACY_PASSWORD})
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(
            self.password_of("mallory"), hashlib.sha1(LEGACY_PASSWORD.encode()).hexdigest()
        )
        # Same password, same row: mallory's matches the two seeded accounts'.
        self.assertEqual(self.password_of("mallory"), self.password_of("carla"))
        self.assertEqual(self.password_of("carla"), self.password_of("davi"))

    def test_django_cannot_check_a_bare_digest_so_the_project_needs_its_own_backend(self):
        self.assertFalse(User.objects.get(username="carla").check_password(LEGACY_PASSWORD))
        _, resp = self.log_in(SECURE_LOGIN, "carla", LEGACY_PASSWORD)
        self.assertEqual(resp.status_code, 401)
        _, resp = self.log_in(VULN_LOGIN, "carla", LEGACY_PASSWORD)
        self.assertEqual(resp.status_code, 200)

    # --- the exploit ---------------------------------------------------------

    def test_the_leak_cracks_and_the_password_reads_carlas_note(self):
        rows = [r for r in leak() if kind(r[1]) == "sha1"]
        result = crack_unsalted(rows, WORDS)
        self.assertEqual(result["found"], {LEGACY_PASSWORD: ["carla", "davi"]})

        client, resp = self.log_in(VULN_LOGIN, "carla", LEGACY_PASSWORD)
        self.assertContains(resp, "logged in as carla")
        self.assertContains(client.get(NOTE), FLAG)

    def test_one_pass_cracks_every_row_that_shares_the_password(self):
        for name in ("eve", "fred", "gina"):
            Client().post(VULN_REGISTER, {"username": name, "password": LEGACY_PASSWORD})
        rows = [r for r in leak() if kind(r[1]) == "sha1"]
        self.assertEqual(len(rows), 5)
        result = crack_unsalted(rows, WORDS)
        # Five accounts, one SHA-1 per guess: the work never asked which account.
        self.assertEqual(result["guesses"], POSITION)
        self.assertEqual(sorted(result["found"][LEGACY_PASSWORD]), ["carla", "davi", "eve", "fred", "gina"])

    # --- the fix, Pattern 1: set_password() ------------------------------------

    def test_secure_register_stores_salted_pbkdf2_and_logs_in_through_django(self):
        for name in ("elisa", "fabio"):
            resp = Client().post(SECURE_REGISTER, {"username": name, "password": LEGACY_PASSWORD})
            self.assertEqual(resp.status_code, 201)
        elisa, fabio = self.password_of("elisa"), self.password_of("fabio")
        algorithm, iterations, salt, _ = elisa.split("$")
        self.assertEqual((algorithm, iterations, len(salt)), ("pbkdf2_sha256", "1000000", 22))
        # Same password, different rows: nothing shared, nothing precomputable.
        self.assertNotEqual(elisa.split("$")[2], fabio.split("$")[2])
        self.assertNotEqual(elisa, fabio)

        client, resp = self.log_in(SECURE_LOGIN, "elisa", LEGACY_PASSWORD)
        self.assertContains(resp, "logged in as elisa")
        self.assertContains(client.get(NOTE), "elisa's notes")

    def test_a_secure_row_does_not_fall_to_the_same_attack(self):
        Client().post(SECURE_REGISTER, {"username": "elisa", "password": LEGACY_PASSWORD})
        [(_, stored)] = leak({"elisa"})
        # Not a row the one-pass lookup can use: it must be attacked alone.
        self.assertEqual(kind(stored), "pbkdf2_sha256")
        result = crack_salted(stored, WORDS, budget=1.0)
        self.assertIsNone(result["password"])
        # A second of PBKDF2 at a million iterations is a handful of guesses; the
        # password is guess 11,007. The margin is three orders of magnitude.
        self.assertLess(result["guesses"], POSITION // 10)

    def test_a_salted_row_still_falls_to_a_guess_that_is_in_the_list(self):
        # Hashing buys time, not immunity: a guess that is right still matches.
        Client().post(SECURE_REGISTER, {"username": "elisa", "password": LEGACY_PASSWORD})
        [(_, stored)] = leak({"elisa"})
        result = crack_salted(stored, ["123456", "password", LEGACY_PASSWORD])
        self.assertEqual((result["password"], result["guesses"]), (LEGACY_PASSWORD, 3))

    # --- the fix, Pattern 2: the rows already in the table ---------------------

    def test_wrapping_converts_every_legacy_row_without_a_password(self):
        out = StringIO()
        call_command("wrap_sha1_hashes", stdout=out)
        self.assertIn("wrapped 2 SHA-1 row(s)", out.getvalue())
        carla, davi = self.password_of("carla"), self.password_of("davi")
        self.assertTrue(carla.startswith("pbkdf2_wrapped_sha1$1000000$"))
        self.assertNotEqual(carla, davi)
        self.assertEqual([r for r in leak() if kind(r[1]) == "sha1"], [])

        # Django checks the wrapped row through PASSWORD_HASHERS.
        self.assertTrue(User.objects.get(username="carla").check_password(LEGACY_PASSWORD))
        # And a guess against it is SHA-1 then a full PBKDF2 run, per row.
        result = crack_salted(carla, ["123456", LEGACY_PASSWORD])
        self.assertEqual((result["password"], result["guesses"]), (LEGACY_PASSWORD, 2))

    def test_a_correct_login_upgrades_a_wrapped_row(self):
        call_command("wrap_sha1_hashes", stdout=StringIO())
        client, resp = self.log_in(SECURE_LOGIN, "carla", LEGACY_PASSWORD)
        self.assertContains(resp, "logged in as carla")
        self.assertTrue(self.password_of("carla").startswith("pbkdf2_sha256$1000000$"))
        self.assertContains(client.get(NOTE), FLAG)

    def test_an_old_leak_still_cracks_after_wrapping_so_the_passwords_need_a_reset(self):
        before = [r for r in leak() if kind(r[1]) == "sha1"]
        call_command("wrap_sha1_hashes", stdout=StringIO())
        cracked = crack_unsalted(before, WORDS)["found"]
        self.assertIn(LEGACY_PASSWORD, cracked)
        _, resp = self.log_in(SECURE_LOGIN, "carla", LEGACY_PASSWORD)
        self.assertEqual(resp.status_code, 200)

        carla = User.objects.get(username="carla")
        carla.set_password("a fresh passphrase nobody leaked")
        carla.save()
        _, resp = self.log_in(SECURE_LOGIN, "carla", LEGACY_PASSWORD)
        self.assertEqual(resp.status_code, 401)

    # --- isolation -----------------------------------------------------------

    def test_the_hasher_list_is_djangos_default_plus_the_wrapper(self):
        self.assertEqual(settings.PASSWORD_HASHERS[:-1], global_settings.PASSWORD_HASHERS)
        self.assertEqual(
            settings.PASSWORD_HASHERS[-1],
            "labs.post_18_password_hashing.hashers.PBKDF2WrappedSHA1PasswordHasher",
        )

    def test_the_note_is_scoped_to_its_owner(self):
        self.assertEqual(Client().get(NOTE).status_code, 401)
        client, _ = self.log_in(VULN_LOGIN, "davi", LEGACY_PASSWORD)
        resp = client.get(NOTE)
        self.assertContains(resp, "davi's notes")
        self.assertNotContains(resp, FLAG)

    def test_the_vulnerable_login_refuses_a_wrong_password(self):
        _, resp = self.log_in(VULN_LOGIN, "carla", "october13")
        self.assertEqual(resp.status_code, 401)
