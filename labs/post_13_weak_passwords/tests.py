"""Runnable proof that the unvalidated registration path stores a password the
lab's own policy forbids — and that one call, in the right place, with both
arguments, closes it.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_13_weak_passwords

``test_one_guess_captures_the_flag`` is the one that matters: it fails the moment
``views_vulnerable.register`` starts calling ``validate_password()``.
"""

import gzip
import tempfile
import urllib.error
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import (
    CommonPasswordValidator,
    MinimumLengthValidator,
    NumericPasswordValidator,
    UserAttributeSimilarityValidator,
    validate_password,
)
from django.core.exceptions import ValidationError
from django.test import Client, TestCase

from .models import Secret
from .policy import get_policy
from .seed import FLAG, STRONG_PASSWORD, VICTIM, VICTIM_EMAIL, VICTIM_PASSWORD
from .validators import BreachListValidator, PwnedPasswordValidator


class WeakPasswordLabTests(TestCase):
    def setUp(self):
        self.carol, _ = User.objects.get_or_create(
            username=VICTIM, defaults={"email": VICTIM_EMAIL}
        )
        self.carol.email = VICTIM_EMAIL
        self.carol.set_password(VICTIM_PASSWORD)
        self.carol.save()
        Secret.objects.filter(owner=self.carol).delete()
        Secret.objects.create(owner=self.carol, body=f"private: {FLAG}")

    # --- the premise: Django's shipped defaults accept the victim's password ---

    def test_djangos_four_default_validators_accept_the_victim_password(self):
        """The `startproject` block — unchanged — says yes to `Password123!`.

        This is the whole reason the lab defines a stricter policy of its own, and it
        is asserted rather than claimed so a future Django release that enlarges
        `common-passwords.txt.gz` turns this test red instead of quietly making
        the post wrong.
        """
        defaults = [
            UserAttributeSimilarityValidator(),
            MinimumLengthValidator(),          # min_length=8, the shipped default
            CommonPasswordValidator(),
            NumericPasswordValidator(),
        ]
        validate_password(VICTIM_PASSWORD, self.carol, password_validators=defaults)

    # --- the bug ---

    def test_vulnerable_register_accepts_a_breached_password(self):
        resp = self.client.post(
            "/passwords/vulnerable/register/",
            {"username": "mallory", "password": VICTIM_PASSWORD},
        )
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(User.objects.filter(username="mallory").exists())
        # And the lab's policy would have said no — the view simply never asked.
        with self.assertRaises(ValidationError):
            validate_password(
                VICTIM_PASSWORD,
                User(username="mallory"),
                password_validators=get_policy(),
            )

    def test_one_guess_captures_the_flag(self):
        # No wordlist walk, no throttle to defeat (that is Lab 11). One guess,
        # because the password was cheap enough to be guessable at rank ~1.
        attacker = Client()
        resp = attacker.post(
            "/accounts/login/", {"username": VICTIM, "password": VICTIM_PASSWORD}
        )
        self.assertEqual(resp.status_code, 200)

        html = attacker.get("/passwords/secret/").content.decode()
        self.assertIn(FLAG, html)

    # --- the fix ---

    def test_secure_register_rejects_the_same_password(self):
        resp = self.client.post(
            "/passwords/secure/register/",
            {"username": "mallory", "password": VICTIM_PASSWORD},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(User.objects.filter(username="mallory").exists())
        body = resp.content.decode()
        # Rejected twice over: below the 15-character floor (Rule 2) AND on the
        # breach blocklist (Rule 4). Neither reason is a composition rule.
        self.assertIn("at least 15 characters", body)
        self.assertIn("known data breach", body)

    def test_secure_register_accepts_a_strong_passphrase(self):
        resp = self.client.post(
            "/passwords/secure/register/",
            {"username": "mallory", "password": STRONG_PASSWORD},
        )
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(
            User.objects.get(username="mallory").check_password(STRONG_PASSWORD)
        )

    def test_flag_is_unreachable_without_the_password(self):
        attacker = Client()
        resp = attacker.post(
            "/accounts/login/", {"username": VICTIM, "password": "not-the-password"}
        )
        self.assertEqual(resp.status_code, 401)
        resp = attacker.get("/passwords/secret/")
        self.assertNotEqual(resp.status_code, 200)  # bounced by @login_required
        self.assertNotIn(FLAG, resp.content.decode())

    # --- the idiomatic fix: the form validates, the view writes ---

    def test_form_register_rejects_the_same_password(self):
        resp = self.client.post(
            "/passwords/form/register/",
            {"username": "mallory", "password": VICTIM_PASSWORD},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(User.objects.filter(username="mallory").exists())
        self.assertIn("known data breach", resp.content.decode())

    def test_form_register_accepts_a_strong_passphrase(self):
        resp = self.client.post(
            "/passwords/form/register/",
            {"username": "mallory", "password": STRONG_PASSWORD},
        )
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(
            User.objects.get(username="mallory").check_password(STRONG_PASSWORD)
        )

    # --- the policy is the lab's, not the project's ---

    def test_the_policy_is_scoped_to_this_lab(self):
        """The project must keep Django's real default so no other lab inherits ours.

        `AUTH_PASSWORD_VALIDATORS` is global. If this lab had set it, the shared
        B7 cast password `labpass` (7 characters) would fail validation in every
        future form-based lab. The policy lives in policy.py instead.
        """
        self.assertEqual(settings.AUTH_PASSWORD_VALIDATORS, [])

        # Under the *project* settings, anything goes — that is Django's default.
        validate_password(VICTIM_PASSWORD, self.carol)
        validate_password("labpass", self.carol)

        # Under the *lab's* policy, both are refused.
        for weak in (VICTIM_PASSWORD, "labpass"):
            with self.assertRaises(ValidationError):
                validate_password(weak, self.carol, password_validators=get_policy())

    # --- the trap: calling the API without the user ---

    def test_validate_password_without_a_user_silently_skips_similarity(self):
        """`UserAttributeSimilarityValidator.validate()` opens `if not user: return`.

        A password identical to the user's own email address is accepted when the
        user argument is omitted, and rejected when it is passed. Same call, same
        settings, one missing argument.
        """
        similarity_only = [UserAttributeSimilarityValidator()]

        # Omitted: the validator no-ops and the email sails through.
        validate_password(
            VICTIM_EMAIL, password_validators=similarity_only
        )

        # Passed: rejected, as intended.
        with self.assertRaises(ValidationError):
            validate_password(
                VICTIM_EMAIL, self.carol, password_validators=similarity_only
            )


class BreachListValidatorTests(TestCase):
    def test_rejects_a_listed_password_case_insensitively(self):
        validator = BreachListValidator()
        for candidate in ("password123!", "Password123!", "  PASSWORD123!  "):
            with self.assertRaises(ValidationError):
                validator.validate(candidate)

    def test_allows_a_password_outside_the_list(self):
        BreachListValidator().validate(STRONG_PASSWORD)

    def test_reads_a_caller_supplied_list(self):
        # The point of the `password_list_path` option: bring your own corpus.
        path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "own.txt.gz"
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write("hunter2forever\n")

        validator = BreachListValidator(password_list_path=path)
        with self.assertRaises(ValidationError):
            validator.validate("HUNTER2FOREVER")
        validator.validate(STRONG_PASSWORD)


class PwnedPasswordValidatorTests(TestCase):
    """The live validator, exercised against a stubbed transport.

    Only `_fetch` is stubbed, so the SHA-1 split, the suffix comparison and the
    threshold logic all stay under test. The lab never calls the real API in CI:
    a suite that depends on a third party's uptime is a suite that goes red for
    reasons that have nothing to do with the code.
    """

    # SHA-1("Password123!") = 49EFEF5F70D47ADC2DB2EB397FBEF5F7BC560E29
    SUFFIX = "F5F70D47ADC2DB2EB397FBEF5F7BC560E29"

    def _validator(self, body=None, error=None, **kwargs):
        validator = PwnedPasswordValidator(**kwargs)
        if error is not None:
            validator._fetch = mock.Mock(side_effect=error)
        else:
            validator._fetch = mock.Mock(return_value=body)
        return validator

    def test_rejects_a_password_present_in_the_range_response(self):
        validator = self._validator(body=f"0000000000000000000000000000000000A:3\n{self.SUFFIX}:295389\n")
        with self.assertRaises(ValidationError):
            validator.validate("Password123!")
        # Only the 5-char prefix ever leaves the process.
        validator._fetch.assert_called_once_with("49EFE")

    def test_allows_a_password_absent_from_the_range_response(self):
        validator = self._validator(body="0000000000000000000000000000000000A:3\n")
        validator.validate("Password123!")

    def test_threshold_lets_rare_passwords_through(self):
        validator = self._validator(
            body=f"{self.SUFFIX}:9\n", threshold=10
        )
        validator.validate("Password123!")

    def test_fail_open_lets_the_password_through_when_the_api_is_down(self):
        validator = self._validator(
            error=urllib.error.URLError("unreachable"), fail_open=True
        )
        validator.validate("Password123!")

    def test_fail_closed_rejects_when_the_api_is_down(self):
        validator = self._validator(
            error=urllib.error.URLError("unreachable"), fail_open=False
        )
        with self.assertRaises(ValidationError) as ctx:
            validator.validate("Password123!")
        self.assertEqual(ctx.exception.error_list[0].code, "pwned_check_unavailable")
