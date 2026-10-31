"""The fix for the rows already in the table: PBKDF2 run over the legacy SHA-1 digest.

Django's documentation ("Password upgrading without requiring a login") gives this
recipe with MD5 as its example; this is the same class for SHA-1. A data migration
(``wrap.py``) replaces every bare 40-character digest with
``encode_sha1_hash(digest, salt)`` — no password needed, because the digest *is*
the input — and ``config/settings.py`` lists the hasher after Django's default so
``check_password()`` can still verify those rows. At each owner's next correct
login, ``check_password()`` sees a hasher other than the first and re-hashes the
password with plain PBKDF2, so the wrapped rows drain away on their own.

``hashlib.sha1`` here is not a weakness: its output never reaches the table bare.
It is the *input* to a million PBKDF2 iterations under a per-row salt.
"""

import hashlib

from django.contrib.auth.hashers import PBKDF2PasswordHasher


class PBKDF2WrappedSHA1PasswordHasher(PBKDF2PasswordHasher):
    algorithm = "pbkdf2_wrapped_sha1"

    def encode_sha1_hash(self, sha1_hash, salt, iterations=None):
        return super().encode(sha1_hash, salt, iterations)

    def encode(self, password, salt, iterations=None):
        sha1_hash = hashlib.sha1(password.encode()).hexdigest()
        return self.encode_sha1_hash(sha1_hash, salt, iterations)
