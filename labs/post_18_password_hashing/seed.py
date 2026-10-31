"""Sample data and the CTF flag for Lab 18. Run via `manage.py seed_labs`.

Seeds two accounts "imported from a legacy system": ``carla`` and ``davi``, whose
``User.password`` holds a bare SHA-1 hex digest, written exactly the way
``views_vulnerable.register()`` writes it. They chose the same password, so their
rows are identical — which a leak shows the attacker before anything is cracked.

That password is ``october12``, guess 11,007 in Django's own 19,640-entry
common-passwords list, the default wordlist of ``crack.py``. It is deliberately
not ``123456``: a password at the top of every list falls on the first guess to
any hasher, however slow (Lab 13's subject). What the hasher decides is the fate
of the passwords further down, so the victims sit further down.

carla's note holds the flag. Each run resets both rows to SHA-1, undoing
``wrap_sha1_hashes`` and any upgrade-on-login, so the lab can be replayed.
Idempotent.
"""

import hashlib

from django.contrib.auth.models import User

from .models import Note

FLAG = "FLAG{unsalted_sha1_cracked_offline}"

LEGACY_PASSWORD = "october12"

LEGACY_ACCOUNTS = {
    "carla": "carla@example.test",
    "davi": "davi@example.test",
}

VICTIM = "carla"


def seed():
    for username, email in LEGACY_ACCOUNTS.items():
        user, _ = User.objects.get_or_create(
            username=username, defaults={"email": email}
        )
        user.email = email
        # Exactly what views_vulnerable.register() does.
        user.password = hashlib.sha1(LEGACY_PASSWORD.encode()).hexdigest()
        user.save()

    victim = User.objects.get(username=VICTIM)
    Note.objects.filter(owner=victim).delete()
    Note.objects.create(owner=victim, body=f"private: {FLAG}")

    return (
        f"seeded legacy accounts {', '.join(LEGACY_ACCOUNTS)} "
        "(unsalted SHA-1, one shared password) + flag note"
    )
