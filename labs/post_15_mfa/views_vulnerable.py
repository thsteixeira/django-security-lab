"""VULNERABLE MFA wiring — the second factor exists, and this door does not ask for it.

Nothing here is missing a feature, which is what makes it worth a lab. ``erin``
has a confirmed ``TOTPDevice``. The project installed ``django-otp``, wired
``OTPMiddleware``, and built a working verify step. Someone did the work.

The mistake is one decorator. ``@login_required`` asks *are you authenticated* —
a question the password already answered. It never asks whether the second factor
was presented **on this session**, because that is a different question with a
different answer, and ``request.user.is_verified()`` is the only thing that
answers it.

So any session that reached ``django.contrib.auth.login()`` by any route walks in.
That matters because MFA rollouts almost never own every route. This repo ships
the shape that bites: a plain password endpoint at ``/accounts/login/`` — the
legacy form, the mobile token exchange, the SSO callback, the management command
that logs someone in for support. The MFA work happened at the *front* door; this
view is a side door that was never told about it.

The secure twin is identical below the decorator, bar the ``# DANGER:`` comment
this repo puts in every vulnerable view. Nothing that runs differs.
"""

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.utils.html import escape

from .models import SensitiveRecord


@login_required
def dashboard(request):
    # DANGER: authentication, not verification. request.user.is_verified() is
    # never consulted here, so a password-only session and a fully MFA'd session
    # are indistinguishable to this view.
    rows = SensitiveRecord.objects.filter(owner=request.user)
    if not rows:
        return HttpResponse(
            f"<h1>Dashboard</h1><p>{escape(request.user.username)} has no records.</p>"
        )
    body = "".join(
        f"<p>{escape(request.user.username)}: {escape(row.body)}</p>" for row in rows
    )
    return HttpResponse(f"<h1>Dashboard</h1>{body}")
