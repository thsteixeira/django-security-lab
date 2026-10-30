"""Sample data and the CTF flag for Lab 17. Run via ``manage.py seed_labs``.

The standard cast (B7), with the roles the post gives them: ``alice`` is the victim,
with a site account at ``alice@example.test`` and a password; ``bob`` is the
attacker. Each also has an account at the in-lab provider, with the same address,
verified. No provider account is connected to any site account at the start.

alice's private note holds the flag. bob never learns alice's password: he changes
his own provider account's email to her address, and signs in.

Idempotent. Re-running restores both passwords, both notes and both provider
accounts, and removes every identity link, every issued code and any user the
vulnerable callback created, so a walkthrough can be repeated.
"""

from django.contrib.auth.models import User

from labs._common.users import CAST, seed_users

from .models import AuthorizationCode, Identity, Note, ProviderAccount

FLAG = "FLAG{oauth2_account_matched_on_email_claim}"

# username -> subject at the provider. Stable, never reassigned.
PROVIDER_SUBJECTS = {"alice": "248289761001", "bob": "248289761002"}


def seed():
    users = seed_users()
    alice, bob = users["alice"], users["bob"]

    Identity.objects.all().delete()
    AuthorizationCode.objects.all().delete()
    # Users the vulnerable callback created for an unknown email are named by subject.
    User.objects.filter(username__in=PROVIDER_SUBJECTS.values()).delete()

    for username, subject in PROVIDER_SUBJECTS.items():
        ProviderAccount.objects.update_or_create(
            username=username,
            defaults={"subject": subject, "email": CAST[username], "email_verified": True},
        )

    Note.objects.filter(owner__in=[alice, bob]).delete()
    Note.objects.create(owner=alice, body=f"recovery codes: {FLAG}")
    Note.objects.create(owner=bob, body="nothing here")

    return (
        "seeded alice (victim, alice@example.test) + bob (attacker), no provider "
        "account connected — alice's note holds the flag"
    )
