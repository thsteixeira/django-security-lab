"""Runnable proof that the hand-rolled login does NOT rotate the session key (so
an attacker's fixed id is promoted to the victim's authenticated session and the
flag leaks), and that ``auth.login()`` DOES rotate it (so the same fixed id stays
anonymous and the flag is out of reach).

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_12_session_fixation

``test_fixation_succeeds_on_vulnerable_view`` is the one that matters: it fails
the moment the vulnerable view is changed to route through ``auth.login()``.
"""

from django.test import Client, TestCase

from labs._common.users import PASSWORD, seed_users

from .models import Secret
from .seed import FLAG


class SessionFixationLabTests(TestCase):
    def setUp(self):
        users = seed_users()
        self.bob = users["bob"]  # the victim
        Secret.objects.filter(owner=self.bob).delete()
        Secret.objects.create(owner=self.bob, body=f"private: {FLAG}")

    def test_login_rotates_the_session_key_on_secure_view(self):
        # The defining property: the session id must CHANGE across login().
        c = Client()
        c.get("/session/whoami/")  # establish a pre-login session
        before = c.session.session_key
        self.assertIsNotNone(before)
        c.post("/session/secure/login/", {"username": "bob", "password": PASSWORD})
        after = c.session.session_key
        self.assertNotEqual(before, after)  # cycle_key() rotated it

    def test_vulnerable_view_does_not_rotate_the_session_key(self):
        c = Client()
        c.get("/session/whoami/")
        before = c.session.session_key
        c.post("/session/vulnerable/login/", {"username": "bob", "password": PASSWORD})
        after = c.session.session_key
        self.assertEqual(before, after)  # promoted in place — no rotation

    def test_fixation_succeeds_on_vulnerable_view(self):
        # 1) Attacker obtains an anonymous session id (the id to fix).
        attacker = Client()
        attacker.get("/session/whoami/")
        fixed = attacker.session.session_key
        self.assertIsNotNone(fixed)

        # 2) Victim (bob) logs in through the vulnerable view carrying that id.
        victim = Client()
        victim.cookies["sessionid"] = fixed
        resp = victim.post(
            "/session/vulnerable/login/", {"username": "bob", "password": PASSWORD}
        )
        self.assertEqual(resp.status_code, 200)

        # 3) The id was promoted in place — the attacker, reusing it, IS bob.
        attacker.cookies["sessionid"] = fixed
        html = attacker.get("/session/secret/").content.decode()
        self.assertIn(FLAG, html)

    def test_fixation_fails_on_secure_view(self):
        attacker = Client()
        attacker.get("/session/whoami/")
        fixed = attacker.session.session_key

        victim = Client()
        victim.cookies["sessionid"] = fixed
        victim.post(
            "/session/secure/login/", {"username": "bob", "password": PASSWORD}
        )
        # login() rotated the key; the fixed id was never promoted.
        attacker.cookies["sessionid"] = fixed
        resp = attacker.get("/session/secret/")
        self.assertNotEqual(resp.status_code, 200)  # bounced by @login_required
        self.assertNotIn(FLAG, resp.content.decode())
