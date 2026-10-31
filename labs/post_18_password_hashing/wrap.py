"""Wrap every legacy SHA-1 row in PBKDF2 — without knowing a single password.

Fixing the sign-up view leaves the imported rows as they were, and a row only
upgrades when its owner logs in again; many never will. This converts them all at
once: each bare 40-character digest becomes
``pbkdf2_wrapped_sha1$<iterations>$<salt>$<hash>``, salted per row and as slow to
guess as a fresh PBKDF2 row.

The function has ``RunPython``'s signature, and ``migrations/0002_wrap_sha1_hashes.py``
runs it as a data migration — the shape a real project ships. In this lab the
legacy rows are seeded *after* ``migrate`` (``docker compose up`` runs migrate,
then ``seed_labs``), so the migration finds nothing to wrap, and
``manage.py wrap_sha1_hashes`` runs the same function on demand.
"""

import re

from .hashers import PBKDF2WrappedSHA1PasswordHasher

SHA1_HEX = re.compile(r"^[0-9a-f]{40}$")


def wrap_sha1_hashes(apps, schema_editor=None):
    User = apps.get_model("auth", "User")
    hasher = PBKDF2WrappedSHA1PasswordHasher()
    wrapped = 0
    for user in User.objects.filter(password__regex=SHA1_HEX.pattern):
        user.password = hasher.encode_sha1_hash(user.password, hasher.salt())
        user.save(update_fields=["password"])
        wrapped += 1
    return wrapped
