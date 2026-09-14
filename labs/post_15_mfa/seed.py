"""Sample data and the CTF flag for Lab 15. Run via ``manage.py seed_labs``.

The victim is ``erin``, and she has done everything right. Her password is a
strong passphrase, and — unlike every other account in this repo — she has a
**confirmed TOTP device**. She is the user who enrolled in MFA when the company
asked her to.

That is the point of the lab. The flag is not reachable because erin was careless;
it is reachable because the application asks the wrong question at the door. An
attacker who has her password (from a breach, a phish, Lab 11, Lab 13 — pick your
route) is supposed to be stopped by the second factor she enrolled in. One
decorator decides whether that is true.

The TOTP key is a fixed constant rather than random so the README walkthrough and
``tests.py`` can both compute a live code. Never do this outside a lab: the key
*is* the second factor, and a shared one is no factor at all.

Idempotent. Re-running restores erin's password and device.
"""

from django.contrib.auth.models import User
from django_otp.plugins.otp_totp.models import TOTPDevice

from .models import SensitiveRecord

FLAG = "FLAG{mfa_enforced_at_login_not_at_the_door}"

VICTIM = "erin"
VICTIM_EMAIL = "erin@example.test"

# Strong on purpose. Guessing the password is not this lab's lesson — Lab 13 owns
# that. Assume the attacker already has it.
VICTIM_PASSWORD = "copper meadow transit fifty"

# 20 bytes of hex, fixed so a reader can generate a valid code from the README.
# In production this is generated per user and never leaves the server.
TOTP_KEY = "3132333435363738393031323334353637383930"


def seed():
    erin, _ = User.objects.get_or_create(
        username=VICTIM, defaults={"email": VICTIM_EMAIL}
    )
    erin.email = VICTIM_EMAIL
    erin.set_password(VICTIM_PASSWORD)
    erin.save()

    TOTPDevice.objects.filter(user=erin).delete()
    TOTPDevice.objects.create(
        user=erin,
        name="erin's authenticator",
        key=TOTP_KEY,
        step=30,
        digits=6,
        tolerance=1,
        confirmed=True,
    )

    SensitiveRecord.objects.filter(owner=erin).delete()
    SensitiveRecord.objects.create(owner=erin, body=f"payout plan: {FLAG}")

    return (
        f"seeded victim '{VICTIM}' WITH a confirmed TOTP device (she enrolled) "
        f"+ flag record behind the dashboards"
    )
