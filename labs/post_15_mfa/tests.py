"""Runnable proof that a password-only session reaches a sensitive view when the
gate asks the wrong question — and that one decorator closes it.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_15_mfa

``test_a_password_only_session_reaches_the_flag`` is the one that matters. It
fails the moment ``views_vulnerable.dashboard`` starts requiring verification.

The last group asserts ``django-otp``'s own throttling. Those tests are not about
this lab's vulnerability at all — they pin library behaviour the post depends on,
so a future release that weakens it turns this repo red instead of quietly making
the post wrong. Same reason Lab 13 asserts that Django's four default validators
accept ``Password123!``.
"""

import time

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice

from .models import SensitiveRecord
from .seed import FLAG, TOTP_KEY, VICTIM, VICTIM_EMAIL, VICTIM_PASSWORD

VULN = "/mfa/vulnerable/dashboard/"
SECURE = "/mfa/secure/dashboard/"
VERIFY = "/mfa/verify/"
LOGIN = "/accounts/login/"


def live_code(device):
    """The code erin's authenticator app would be showing right now."""
    totp = TOTP(device.bin_key, device.step, device.t0, device.digits, device.drift)
    totp.time = time.time()
    return f"{totp.token():06d}"


class MfaLabTests(TestCase):
    def setUp(self):
        self.erin, _ = User.objects.get_or_create(
            username=VICTIM, defaults={"email": VICTIM_EMAIL}
        )
        self.erin.email = VICTIM_EMAIL
        self.erin.set_password(VICTIM_PASSWORD)
        self.erin.save()

        TOTPDevice.objects.filter(user=self.erin).delete()
        self.device = TOTPDevice.objects.create(
            user=self.erin,
            name="erin's authenticator",
            key=TOTP_KEY,
            step=30,
            digits=6,
            tolerance=1,
            confirmed=True,
        )

        SensitiveRecord.objects.filter(owner=self.erin).delete()
        SensitiveRecord.objects.create(owner=self.erin, body=f"payout plan: {FLAG}")

    # helpers -----------------------------------------------------------------

    def password_only_session(self):
        """Exactly what an attacker holding the password gets: a session that
        authenticated and never saw a second factor."""
        c = Client()
        resp = c.post(LOGIN, {"username": VICTIM, "password": VICTIM_PASSWORD})
        self.assertEqual(resp.status_code, 200, "password login should succeed")
        return c

    def fully_verified_session(self):
        c = self.password_only_session()
        resp = c.post(VERIFY, {"code": live_code(self.device)})
        self.assertEqual(resp.status_code, 200, resp.content)
        return c

    # --- the premise ---------------------------------------------------------

    def test_erin_enrolled_and_her_password_is_not_the_way_in(self):
        """She did the right thing; the lab is not about a careless user."""
        self.assertTrue(
            TOTPDevice.objects.filter(user=self.erin, confirmed=True).exists()
        )
        for guess in ["password", "Password123!", "erin", VICTIM_EMAIL]:
            self.assertEqual(
                Client().post(LOGIN, {"username": VICTIM, "password": guess}).status_code,
                401,
                guess,
            )

    def test_a_password_only_session_is_authenticated_but_not_verified(self):
        """The two flags the whole lab turns on."""
        c = self.password_only_session()
        resp = c.get(VULN)
        self.assertTrue(resp.wsgi_request.user.is_authenticated)
        self.assertFalse(resp.wsgi_request.user.is_verified())

    # --- the bug -------------------------------------------------------------

    def test_a_password_only_session_reaches_the_flag(self):
        """The exploit: no second factor, no code, no device — just the password."""
        resp = self.password_only_session().get(VULN)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(FLAG, resp.content.decode())

    # --- the fix -------------------------------------------------------------

    def test_the_same_session_is_refused_by_the_secure_dashboard(self):
        resp = self.password_only_session().get(SECURE)
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn(FLAG, resp.content.decode(errors="ignore"))

    def test_the_secure_dashboard_serves_a_fully_verified_session(self):
        """A control that blocks the attacker and the user is not a control."""
        resp = self.fully_verified_session().get(SECURE)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(FLAG, resp.content.decode())

    def test_it_is_otp_login_that_flips_is_verified(self):
        """Verifying a code is not enough on its own — the session has to be told.

        Checking the token and forgetting to call django_otp.login() is a real
        and quiet way to end up with MFA that verifies nothing.
        """
        c = self.fully_verified_session()
        resp = c.get(SECURE)
        self.assertTrue(resp.wsgi_request.user.is_verified())
        self.assertEqual(resp.wsgi_request.user.otp_device.pk, self.device.pk)

    def test_verification_does_not_leak_across_sessions(self):
        """erin verifying on her laptop must not verify the attacker's session."""
        self.fully_verified_session()
        self.assertEqual(self.password_only_session().get(SECURE).status_code, 302)

    # --- the verify step -----------------------------------------------------

    def test_verify_requires_a_login_first(self):
        self.assertEqual(Client().post(VERIFY, {"code": "000000"}).status_code, 401)

    def test_a_wrong_code_is_refused(self):
        c = self.password_only_session()
        self.assertEqual(c.post(VERIFY, {"code": "000000"}).status_code, 401)
        self.assertEqual(c.get(SECURE).status_code, 302)

    # --- the sweep: the detection that actually works ------------------------

    def test_sweep_reports_which_urls_a_password_only_session_can_reach(self):
        """No standard scanner finds this class, and the policy rule sees only code.

        The technique generalises and is the one thing worth copying out of this
        lab: enumerate the URLs that are supposed to sit behind the second
        factor, drive each one with a session that only ever presented a
        password, and collect the ones that answer 200.

        In your project the assertion is ``assertEqual(reachable, [])``. Here it
        is deliberately non-empty, because that is the bug — and writing it this
        way means the sweep is demonstrated doing its job rather than asserted in
        the abstract.
        """
        protected_area = [VULN, SECURE]
        attacker = self.password_only_session()

        reachable = [url for url in protected_area if attacker.get(url).status_code == 200]

        self.assertEqual(reachable, [VULN])
        self.assertNotIn(SECURE, reachable)

    # --- django-otp's own throttling (library behaviour, pinned) -------------

    def test_django_otp_throttles_from_the_very_first_failed_code(self):
        """Why this lab ships no 'unthrottled OTP' view: there isn't one to ship.

        One wrong code is enough to put the device into backoff. The counter and
        its timestamp live on the device row, so this holds across processes and
        restarts — unlike a cache-based counter written by hand.
        """
        self.assertTrue(self.device.verify_is_allowed()[0])

        self.assertFalse(self.device.verify_token("000000"))

        allowed, data = self.device.verify_is_allowed()
        self.assertFalse(allowed, "one failure should already throttle")
        self.assertEqual(self.device.throttling_failure_count, 1)
        self.assertIn("locked_until", data)

    def test_while_throttled_even_the_correct_code_is_refused(self):
        """The part that makes brute force pointless rather than merely slow."""
        self.device.verify_token("000000")
        self.assertFalse(self.device.verify_token(live_code(self.device)))

    def test_the_backoff_doubles(self):
        """Required delay after 1, 2, 3, 4, 5 failures: 1, 2, 4, 8, 16 seconds.

        Literal values, not the library's formula, so a release that flattens or
        slows the curve fails here. A refused verify_token() does not increment
        the counter, so the failures are recorded with throttle_increment()
        directly — the first test above pins that verify_token() calls it.
        Asserted against the model's own fields rather than by sleeping, so the
        suite stays fast and deterministic.
        """
        self.assertEqual(self.device.get_throttle_factor(), 1)
        for expected in (1, 2, 4, 8, 16):
            self.device.throttle_increment(commit=True)
            allowed, data = self.device.verify_is_allowed()
            self.assertFalse(allowed)
            delay = (data["locked_until"] - self.device.throttling_failure_timestamp).total_seconds()
            self.assertEqual(delay, expected)
