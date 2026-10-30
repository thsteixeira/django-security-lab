"""Runnable proof that a "log in with the provider" callback which finds the account by
the ID token's ``email`` logs the attacker into the victim's account — and that
finding it by ``(iss, sub)`` closes it.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_17_oauth2

``test_bobs_provider_account_with_alices_email_signs_in_as_alice`` and
``test_secure_refuses_bobs_provider_account`` are the pair that matters: the same
provider sign-in, by bob, with alice's address on his provider account, logged in
as alice by one callback and refused by the other.
"""

import jwt
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse

from labs._common.users import PASSWORD

from . import idp, provider, views_connect, views_secure, views_vulnerable
from .models import Identity
from .seed import FLAG, seed

VULN_LOGIN = "/oauth2/vulnerable/login/"
SECURE_LOGIN = "/oauth2/secure/login/"
CONNECT = "/oauth2/connect/"
ACCOUNT = "/oauth2/account/"
PROFILE = "/oauth2/provider/profile/"


class OAuth2LabTests(TestCase):
    def setUp(self):
        seed()

    # helpers -----------------------------------------------------------------

    def callback_url(self, client, start, as_user, password=None):
        """Start a flow, sign in at the provider, and return the callback URL. The
        connect flow starts with a POST carrying the user's password."""
        if password is None:
            start_resp = client.get(start)
        else:
            start_resp = client.post(start, {"password": password})
        self.assertEqual(start_resp.status_code, 302)
        provider_resp = client.get(f"{start_resp['Location']}&as={as_user}")
        self.assertEqual(provider_resp.status_code, 302, provider_resp.content)
        return provider_resp["Location"]

    def sign_in_with_provider(self, client, start, as_user):
        return client.get(self.callback_url(client, start, as_user))

    def bob_claims_alices_email(self):
        resp = Client().get(PROFILE, {"as": "bob", "email": "alice@example.test"})
        self.assertContains(resp, "(unverified)")

    # --- the exploit -----------------------------------------------------------

    def test_bobs_provider_account_with_alices_email_signs_in_as_alice(self):
        self.bob_claims_alices_email()
        bob = Client()
        resp = self.sign_in_with_provider(bob, VULN_LOGIN, "bob")
        self.assertContains(resp, "logged in as alice")
        self.assertContains(bob.get(ACCOUNT), FLAG)

    # --- the fix ---------------------------------------------------------------

    def test_secure_refuses_bobs_provider_account(self):
        self.bob_claims_alices_email()
        bob = Client()
        resp = self.sign_in_with_provider(bob, SECURE_LOGIN, "bob")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(bob.get(ACCOUNT).status_code, 302)  # not signed in

    def test_secure_ignores_even_a_verified_email_nobody_connected(self):
        """alice's own provider account, verified address and all, opens nothing until
        alice connects it: the email is never the key."""
        resp = self.sign_in_with_provider(Client(), SECURE_LOGIN, "alice")
        self.assertEqual(resp.status_code, 403)

    # --- the secure view still does its job ------------------------------------

    def test_alice_connects_her_provider_account_and_signs_in_with_it(self):
        alice = Client()
        alice.login(username="alice", password=PASSWORD)
        connected = alice.get(self.callback_url(alice, CONNECT, "alice", PASSWORD))
        self.assertContains(connected, "to alice")

        fresh = Client()
        resp = self.sign_in_with_provider(fresh, SECURE_LOGIN, "alice")
        self.assertContains(resp, "logged in as alice")
        self.assertContains(fresh.get(ACCOUNT), FLAG)

    def test_and_a_changed_email_does_not_move_her_identity(self):
        alice = Client()
        alice.login(username="alice", password=PASSWORD)
        alice.get(self.callback_url(alice, CONNECT, "alice", PASSWORD))
        Client().get(PROFILE, {"as": "alice", "email": "alice@new-employer.test"})
        resp = self.sign_in_with_provider(Client(), SECURE_LOGIN, "alice")
        self.assertContains(resp, "logged in as alice")

    # --- what is neutralised, so this lab teaches one thing ---------------------

    def test_every_callback_refuses_a_missing_state(self):
        for start in (VULN_LOGIN, SECURE_LOGIN):
            with self.subTest(start=start):
                client = Client()
                callback = self.callback_url(client, start, "alice")
                self.assertEqual(client.get(callback.split("&state=")[0]).status_code, 400)

    def test_connect_cannot_be_finished_in_someone_elses_session(self):
        bob = Client()
        bob.login(username="bob", password=PASSWORD)
        alice = Client()
        alice.login(username="alice", password=PASSWORD)
        alice.post(CONNECT, {"password": PASSWORD})  # alice has a connect flow of her own open
        resp = alice.get(self.callback_url(bob, CONNECT, "bob", PASSWORD))
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(Identity.objects.exists())

    def test_connect_asks_for_the_password_again(self):
        """A session alone links nothing. bob, holding alice's session from the
        vulnerable callback, cannot connect his provider account to her and so cannot
        carry the takeover into the secure callback."""
        self.bob_claims_alices_email()
        bob = Client()
        self.sign_in_with_provider(bob, VULN_LOGIN, "bob")  # bob is in alice's session
        self.assertEqual(bob.get(CONNECT).status_code, 405)
        self.assertEqual(bob.post(CONNECT).status_code, 403)
        self.assertEqual(bob.post(CONNECT, {"password": PASSWORD + "-guess"}).status_code, 403)
        self.assertFalse(Identity.objects.exists())
        resp = self.sign_in_with_provider(Client(), SECURE_LOGIN, "bob")
        self.assertEqual(resp.status_code, 403)

    def test_an_id_token_for_another_client_is_refused(self):
        token = jwt.encode(
            {"iss": provider.ISSUER, "sub": "1", "aud": "another-app", "iat": 0, "exp": 2**31},
            provider.CLIENT_SECRET,
            algorithm="HS256",
        )
        with self.assertRaises(jwt.InvalidAudienceError):
            idp.verify_id_token(token)

    def test_a_code_is_redeemed_once_and_only_at_its_redirect_uri(self):
        callback = self.callback_url(Client(), VULN_LOGIN, "alice")
        code = callback.split("code=")[1].split("&")[0]
        with self.assertRaises(provider.InvalidGrant):
            idp.exchange_code(code, redirect_uri=views_secure.CALLBACK)
        idp.exchange_code(code, redirect_uri=views_vulnerable.CALLBACK)
        with self.assertRaises(provider.InvalidGrant):
            idp.exchange_code(code, redirect_uri=views_vulnerable.CALLBACK)

    def test_the_provider_refuses_an_unregistered_redirect_uri(self):
        url = idp.authorization_url(redirect_uri="https://attacker.example/cb") + "&as=bob"
        self.assertEqual(Client().get(url).status_code, 400)

    def test_callback_constants_match_the_routes(self):
        self.assertEqual(reverse("oauth2_vulnerable_callback"), views_vulnerable.CALLBACK)
        self.assertEqual(reverse("oauth2_secure_callback"), views_secure.CALLBACK)
        self.assertEqual(reverse("oauth2_connect_callback"), views_connect.CALLBACK)

    def test_seed_leaves_no_user_behind_from_the_vulnerable_callback(self):
        Client().get(PROFILE, {"as": "bob", "email": "nobody@example.test"})
        self.sign_in_with_provider(Client(), VULN_LOGIN, "bob")
        self.assertTrue(User.objects.filter(username="248289761002").exists())
        seed()
        self.assertFalse(User.objects.filter(username="248289761002").exists())
