"""Sample data and the CTF flag for Lab 14. Run via ``manage.py seed_labs``.

The victim is ``dave``, and his password is deliberately **strong** — a
four-word passphrase that clears Lab 13's policy comfortably. That matters: this
lab must not be quietly winnable by guessing. The only way into dave's account is
the reset flow, which is the point.

What the seed plants beside him is a ``ResetToken`` issued **400 days ago**. It
stands in for the thing that actually happens: a reset link that got out. Reset
URLs are ordinary URLs, and ordinary URLs end up in reverse-proxy access logs,
browser history, corporate TLS-inspection appliances, ``Referer`` headers sent
from the reset confirmation page to whatever it loads, and mailbox backups that
outlive the account. The interesting question is never "can an attacker guess the
token" — ``uuid4`` says no. It is "how long does a token that leaked stay
valuable", and this flow answers: forever.

The token string is a fixed constant rather than a fresh ``uuid4`` so the README
walkthrough can quote a URL the reader can paste. The user's pk is not fixed, so
the seed prints the ``uidb64`` half; read it from the seed output.

Idempotent. Re-running restores dave's password, so a lab you have already
exploited resets to the starting position.
"""

from datetime import timedelta

from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .models import ResetToken, VaultItem

FLAG = "FLAG{reset_link_from_last_year_still_worked}"

VICTIM = "dave"
VICTIM_EMAIL = "dave@example.test"

# Strong on purpose: guessing is not the intended path into this account.
VICTIM_PASSWORD = "orbit lantern drawer ninety"

# A reset link that leaked. Fixed so the README can quote the full URL.
LEAKED_TOKEN = "6f1c1e2a-9b7d-4a3f-8c21-0d5e7a9b4c33"
LEAKED_TOKEN_AGE = timedelta(days=400)

# Nobody has an account at this address. The vulnerable request view says so;
# the secure one declines to comment.
UNKNOWN_EMAIL = "nobody@example.test"


def seed():
    dave, _ = User.objects.get_or_create(
        username=VICTIM, defaults={"email": VICTIM_EMAIL}
    )
    dave.email = VICTIM_EMAIL
    dave.set_password(VICTIM_PASSWORD)
    dave.save()

    ResetToken.objects.filter(user=dave).delete()
    ResetToken.objects.create(
        user=dave,
        token=LEAKED_TOKEN,
        created=timezone.now() - LEAKED_TOKEN_AGE,
    )

    VaultItem.objects.filter(owner=dave).delete()
    VaultItem.objects.create(owner=dave, body=f"recovery codes: {FLAG}")

    uidb64 = urlsafe_base64_encode(force_bytes(dave.pk))
    return (
        f"seeded victim '{VICTIM}' (strong password) + a reset token issued "
        f"{LEAKED_TOKEN_AGE.days} days ago + flag vault item. "
        f"Leaked link: /password-reset/vulnerable/confirm/{uidb64}/{LEAKED_TOKEN}/"
    )
