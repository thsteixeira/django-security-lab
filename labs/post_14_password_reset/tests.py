"""Runnable proof that a hand-rolled reset token is a permanent credential, and
that Django's token generator makes it a temporary one — without adding a single
branch to the confirm view.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_14_password_reset

``test_a_leaked_year_old_token_still_takes_over_the_account`` is the one that
matters. It fails the moment ``views_vulnerable.confirm`` starts reading either of
the two columns it already writes.

Three tests carry an ``@override_settings(ALLOWED_HOSTS=["*"])``. That is not a
convenience — it is the experiment. ``ALLOWED_HOSTS`` is what stops host-header
poisoning in this lab (``test_allowed_hosts_is_what_actually_blocks_the_poisoned_host``
proves it, unoverridden), and ``["*"]`` is the single most common way real projects
switch it off. The override reproduces that project, so the two link builders can
be compared with the framework's backstop removed.
"""

import re
from datetime import datetime, timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .helpers import RESET_BASE_URL
from .models import ResetToken, VaultItem
from .seed import (
    FLAG,
    LEAKED_TOKEN,
    LEAKED_TOKEN_AGE,
    UNKNOWN_EMAIL,
    VICTIM,
    VICTIM_EMAIL,
    VICTIM_PASSWORD,
)

ATTACKER_PASSWORD = "the attacker picks this one"

VULN_REQUEST = "/password-reset/vulnerable/request/"
SECURE_REQUEST = "/password-reset/secure/request/"
VAULT = "/password-reset/vault/"


def link_in_last_email():
    """Pull the reset URL out of the message the view just sent."""
    match = re.search(r"https?://\S+", mail.outbox[-1].body)
    return match.group(0) if match else ""


class PasswordResetLabTests(TestCase):
    def setUp(self):
        self.dave, _ = User.objects.get_or_create(
            username=VICTIM, defaults={"email": VICTIM_EMAIL}
        )
        self.dave.email = VICTIM_EMAIL
        self.dave.set_password(VICTIM_PASSWORD)
        self.dave.save()
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.dave.pk))

        ResetToken.objects.filter(user=self.dave).delete()
        self.leaked = ResetToken.objects.create(
            user=self.dave,
            token=LEAKED_TOKEN,
            created=timezone.now() - LEAKED_TOKEN_AGE,
        )

        VaultItem.objects.filter(owner=self.dave).delete()
        VaultItem.objects.create(owner=self.dave, body=f"recovery codes: {FLAG}")

        mail.outbox = []

    # helpers -----------------------------------------------------------------

    def vuln_confirm(self, token, password=ATTACKER_PASSWORD, uidb64=None):
        return self.client.post(
            f"/password-reset/vulnerable/confirm/{uidb64 or self.uidb64}/{token}/",
            {"password": password},
        )

    def secure_confirm(self, token, password=ATTACKER_PASSWORD, uidb64=None):
        return self.client.post(
            f"/password-reset/secure/confirm/{uidb64 or self.uidb64}/{token}/",
            {"password": password},
        )

    def login(self, password):
        return Client().post(
            "/accounts/login/", {"username": VICTIM, "password": password}
        )

    # --- the premise: the account is not reachable by guessing ---------------

    def test_the_victim_password_is_not_the_way_in(self):
        """This lab must not be quietly winnable as a weak-password lab (Post 13).

        Dave's passphrase is long, unguessable and in no wordlist. Every route into
        his account other than the reset flow is closed, which is what makes the
        reset flow the whole story.
        """
        for guess in ["password", "Password123!", "dave", VICTIM_EMAIL]:
            self.assertEqual(self.login(guess).status_code, 401, guess)
        self.assertEqual(self.login(VICTIM_PASSWORD).status_code, 200)

    def test_the_vault_is_not_readable_without_a_session(self):
        resp = Client().get(VAULT)
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn(FLAG, resp.content.decode(errors="ignore"))

    # --- the bug: the token is a permanent credential ------------------------

    def test_a_leaked_year_old_token_still_takes_over_the_account(self):
        """The exploit, end to end: leaked link in, flag out.

        Nothing here guesses anything. The attacker holds one URL that was valid
        over a year ago — the kind that survives in a proxy log or a mailbox
        backup — and the flow has no opinion about how old that is.
        """
        self.assertGreater(
            (timezone.now() - self.leaked.created).days,
            365,
            "the seeded token should be more than a year old",
        )

        resp = self.vuln_confirm(LEAKED_TOKEN)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("password updated", resp.content.decode())

        attacker = Client()
        self.assertEqual(
            attacker.post(
                "/accounts/login/",
                {"username": VICTIM, "password": ATTACKER_PASSWORD},
            ).status_code,
            200,
        )

        vault = attacker.get(VAULT)
        self.assertEqual(vault.status_code, 200)
        self.assertIn(FLAG, vault.content.decode())

    def test_the_vulnerable_token_is_reusable_because_used_at_is_never_read(self):
        """``used_at`` is written, and writing it changes nothing.

        The first call marks the row spent. The second call reads the same row,
        sees the timestamp, and proceeds anyway — because no branch looks. A
        single-use token that is not enforced as single-use is just a password
        with extra steps.
        """
        self.assertEqual(self.vuln_confirm(LEAKED_TOKEN, "first pass phrase").status_code, 200)

        self.leaked.refresh_from_db()
        self.assertIsNotNone(self.leaked.used_at, "the view does record the use")

        self.assertEqual(self.vuln_confirm(LEAKED_TOKEN, "second pass phrase").status_code, 200)
        self.assertEqual(self.login("second pass phrase").status_code, 200)

    def test_the_vulnerable_flow_scopes_the_token_to_its_own_user(self):
        """The one check it does make, so the failure above is not just sloppiness.

        The token is bound to a user; a token belonging to someone else is refused.
        This flow is not careless — it is careless about exactly two things.
        """
        mallory = User.objects.create_user(
            username="mallory", email="mallory@example.test", password="unimportant here"
        )
        resp = self.vuln_confirm(
            LEAKED_TOKEN, uidb64=urlsafe_base64_encode(force_bytes(mallory.pk))
        )
        self.assertEqual(resp.status_code, 400)

    # --- the fix: the same leaked token buys nothing -------------------------

    def test_secure_confirm_rejects_the_leaked_token(self):
        resp = self.secure_confirm(LEAKED_TOKEN)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("invalid or expired", resp.content.decode())

        self.dave.refresh_from_db()
        self.assertTrue(self.dave.check_password(VICTIM_PASSWORD))
        self.assertEqual(self.login(ATTACKER_PASSWORD).status_code, 401)

    def test_secure_token_expires_on_its_own(self):
        """No stored expiry, no cleanup job: the timestamp is inside the hash.

        Time is moved forward rather than the token aged, because there is nothing
        to age — the token is not a row.
        """
        token = default_token_generator.make_token(self.dave)
        self.assertTrue(default_token_generator.check_token(self.dave, token))

        later = datetime.now() + timedelta(seconds=settings_timeout() + 60)
        with mock.patch.object(default_token_generator, "_now", return_value=later):
            self.assertFalse(default_token_generator.check_token(self.dave, token))
            self.assertEqual(self.secure_confirm(token).status_code, 400)

    def test_secure_token_is_retired_by_the_reset_it_performs(self):
        """One use, then nothing — without a ``used_at`` column anywhere."""
        token = default_token_generator.make_token(self.dave)
        self.assertEqual(self.secure_confirm(token, "a brand new pass phrase").status_code, 200)
        self.assertEqual(self.secure_confirm(token, ATTACKER_PASSWORD).status_code, 400)
        self.assertEqual(self.login(ATTACKER_PASSWORD).status_code, 401)

    def test_secure_token_is_invalidated_by_a_password_change_elsewhere(self):
        """The outstanding-link case: the user remembers the password mid-reset.

        They change it in account settings and never click the email. The link in
        their inbox dies on its own, because ``user.password`` is part of what the
        token hashes.
        """
        token = default_token_generator.make_token(self.dave)
        self.dave.set_password("changed it in settings instead")
        self.dave.save()

        self.assertFalse(default_token_generator.check_token(self.dave, token))
        self.assertEqual(self.secure_confirm(token).status_code, 400)

    # --- host-header poisoning ----------------------------------------------

    def test_allowed_hosts_is_what_actually_blocks_the_poisoned_host(self):
        """Unoverridden, so this is the lab's real configuration.

        The vulnerable view builds its link from the request host and would happily
        put ``evil.test`` in an email — but the request never reaches it. Django
        validates ``Host`` against ``ALLOWED_HOSTS`` first and raises
        ``DisallowedHost``. This is the control, and it is a framework setting
        rather than anything in the view.
        """
        resp = self.client.post(
            VULN_REQUEST, {"email": VICTIM_EMAIL}, HTTP_HOST="evil.test"
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(mail.outbox, [])

    @override_settings(ALLOWED_HOSTS=["*"])
    def test_with_allowed_hosts_open_the_vulnerable_link_is_poisoned(self):
        """The common misconfiguration, and what it costs.

        With the backstop removed, a header the attacker controls decides the
        domain of a link the server mails to the victim. The victim clicks their
        own reset link and hands the token to whoever is listening there.
        """
        resp = self.client.post(
            VULN_REQUEST, {"email": VICTIM_EMAIL}, HTTP_HOST="evil.test"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("http://evil.test/", link_in_last_email())

    @override_settings(ALLOWED_HOSTS=["*"])
    def test_with_allowed_hosts_open_the_secure_link_is_still_canonical(self):
        """Same request, same open setting, different link builder.

        This is the point of taking the host from configuration: the control does
        not depend on ``ALLOWED_HOSTS`` being right.
        """
        resp = self.client.post(
            SECURE_REQUEST, {"email": VICTIM_EMAIL}, HTTP_HOST="evil.test"
        )
        self.assertEqual(resp.status_code, 200)
        link = link_in_last_email()
        self.assertTrue(link.startswith(RESET_BASE_URL), link)
        self.assertNotIn("evil.test", link)

    # --- account enumeration -------------------------------------------------

    def test_vulnerable_request_reveals_whether_an_account_exists(self):
        known = self.client.post(VULN_REQUEST, {"email": VICTIM_EMAIL})
        unknown = self.client.post(VULN_REQUEST, {"email": UNKNOWN_EMAIL})

        self.assertEqual(known.status_code, 200)
        self.assertEqual(unknown.status_code, 404)
        self.assertNotEqual(known.content, unknown.content)

    def test_secure_request_answers_identically_either_way(self):
        known = self.client.post(SECURE_REQUEST, {"email": VICTIM_EMAIL})
        unknown = self.client.post(SECURE_REQUEST, {"email": UNKNOWN_EMAIL})

        self.assertEqual(known.status_code, unknown.status_code)
        self.assertEqual(known.content, unknown.content)
        # ...and only one of them actually sent anything.
        self.assertEqual(len(mail.outbox), 1)

    # --- the secure flow still does its job ---------------------------------

    def test_the_secure_flow_still_resets_a_password_end_to_end(self):
        """A control that blocks the attack and the user is not a control.

        Drives the real path: request, read the mailed link, follow it, set a new
        password, log in, read your own vault.
        """
        self.assertEqual(
            self.client.post(SECURE_REQUEST, {"email": VICTIM_EMAIL}).status_code, 200
        )
        link = link_in_last_email()
        self.assertTrue(link.startswith(RESET_BASE_URL), link)

        path = link[len(RESET_BASE_URL) :]
        new_password = "dave picks a fresh pass phrase"
        resp = self.client.post(path, {"password": new_password})
        self.assertEqual(resp.status_code, 200)

        dave = Client()
        self.assertEqual(
            dave.post(
                "/accounts/login/", {"username": VICTIM, "password": new_password}
            ).status_code,
            200,
        )
        self.assertIn(FLAG, dave.get(VAULT).content.decode())


def settings_timeout():
    from django.conf import settings

    return settings.PASSWORD_RESET_TIMEOUT
