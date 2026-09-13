"""Two pieces both halves of the lab need, kept out of the view files so the
vulnerable/secure diff stays about the reset logic itself.

``RESET_BASE_URL`` is the interesting one. A reset link has to name a host, and
there are exactly two places that host can come from: the incoming request, or
configuration. Taking it from the request (``request.build_absolute_uri()``) is
the default every tutorial reaches for, and it is what turns a ``Host`` header
into a rewrite of the link you are about to email a user. Taking it from
configuration cannot be influenced by the request at all.

In a real project this constant is a setting, ``django.contrib.sites``, or the
``domain_override``/``request`` pair that ``PasswordResetForm.save()`` already
accepts. The principle does not change with the mechanism: the canonical domain
is something you know, not something the client tells you.
"""

from django.contrib.auth.models import User
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

# Configuration, not request data. Nothing a client sends can move this.
RESET_BASE_URL = "http://127.0.0.1:8000"


def build_reset_link(path):
    return f"{RESET_BASE_URL}{path}"


def user_from_uidb64(uidb64):
    """Decode the ``uidb64`` half of a reset URL, or return None.

    ``uidb64`` is base64, not a signature — it identifies the account, it does not
    authenticate anything. The token is the only secret in the URL. Both halves of
    this lab decode it identically; they differ only in what they then do with the
    token.
    """
    try:
        return User.objects.get(pk=force_str(urlsafe_base64_decode(uidb64)))
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return None
