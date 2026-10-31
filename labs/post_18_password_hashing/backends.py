"""VULNERABLE — the authentication backend a hand-hashed password column needs.

Django cannot check a bare SHA-1 digest: ``check_password()`` finds no hasher it
recognises in a string with no ``algorithm$`` prefix, runs a dummy hash to keep
the timing even, and returns ``False``. So a project that writes
``hashlib.sha1(password).hexdigest()`` into ``User.password`` cannot use Django's
login at all, and this backend is what it writes next. The two travel together.

In a real project this class would sit in ``AUTHENTICATION_BACKENDS``. Here only
the vulnerable login view (``views_vulnerable.login``) calls it, because that
setting is global and would otherwise let SHA-1 rows in through every lab's login
— including the shared ``/accounts/login/``, which is this lab's secure login.
"""

import hashlib

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User


class SHA1Backend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        user = User.objects.filter(username=username).first()
        if user and user.password == hashlib.sha1(password.encode()).hexdigest():
            return user
