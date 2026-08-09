"""Runnable proof that the @csrf_exempt view accepts a tokenless (forged) POST
and moves the flag, that the @csrf_protect view rejects the same POST with 403,
and that a legitimate tokened POST still works.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_08_csrf

**What these assert.** `Client(enforce_csrf_checks=True)` is essential — the
default test client bypasses CSRF entirely, so a lab tested with it would pass
while proving nothing. A tokenless POST is the shape a cross-site forgery
produces: it carries the victim's session cookie but no CSRF token.
"""

import re

from django.contrib.auth.models import User
from django.test import Client, TestCase

from .models import Account
from .seed import FLAG


class CsrfLabTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user("alice", password="labpass")
        self.bob = User.objects.create_user("bob", password="labpass")
        Account.objects.create(user=self.alice, holdings=FLAG)  # victim
        Account.objects.create(user=self.bob, holdings="")       # attacker
        self.client = Client(enforce_csrf_checks=True)

    def holdings(self, user):
        return Account.objects.get(user=user).holdings

    def test_exploit_succeeds_on_vulnerable_view(self):
        # A tokenless POST (the forged-request shape) goes through: the flag moves
        # from the victim to the attacker's account.
        self.client.force_login(self.alice)
        self.client.post("/csrf/vulnerable/transfer/", {"to_account": "bob"})
        self.assertEqual(self.holdings(self.bob), FLAG)
        self.assertEqual(self.holdings(self.alice), "")

    def test_exploit_is_blocked_on_secure_view(self):
        # @csrf_protect rejects the tokenless POST with 403; nothing moves.
        self.client.force_login(self.alice)
        resp = self.client.post("/csrf/secure/transfer/", {"to_account": "bob"})
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(self.holdings(self.alice), FLAG)
        self.assertEqual(self.holdings(self.bob), "")

    def test_legit_tokened_transfer_succeeds_on_secure_view(self):
        # A real same-origin user gets a token from the form and can transfer —
        # the fix rejects forgeries, not legitimate use.
        self.client.force_login(self.alice)
        form = self.client.get("/csrf/secure/transfer/").content.decode()
        token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', form).group(1)
        self.client.post(
            "/csrf/secure/transfer/",
            {"to_account": "bob", "csrfmiddlewaretoken": token},
        )
        self.assertEqual(self.holdings(self.bob), FLAG)
