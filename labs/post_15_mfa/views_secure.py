"""SECURE MFA wiring — one decorator, asking the right question.

``@otp_required`` is a thin wrapper that requires ``request.user.is_verified()``
in addition to authentication. That flag is True only when
``django_otp.login(request, device)`` has recorded a verified device **on this
session** — which happens in exactly one place, ``views_verify.py``, after a code
actually checked out.

So the question at the door changes from "did you authenticate" to "did you
present the second factor on this session", and the password-only side door stops
being a way in. Every executable line below the decorator is identical to the
vulnerable twin — only its ``# DANGER:`` comment differs — so diff the two files
and the entire vulnerability is one line.

Worth saying plainly: no new library, no new middleware, no re-implementation of
anything. ``django-otp`` was already installed and already correct. This class is
in scope because the bug is in the wiring, not in the package.
"""

from django.http import HttpResponse
from django.utils.html import escape
from django_otp.decorators import otp_required

from .models import SensitiveRecord


@otp_required
def dashboard(request):
    rows = SensitiveRecord.objects.filter(owner=request.user)
    if not rows:
        return HttpResponse(
            f"<h1>Dashboard</h1><p>{escape(request.user.username)} has no records.</p>"
        )
    body = "".join(
        f"<p>{escape(request.user.username)}: {escape(row.body)}</p>" for row in rows
    )
    return HttpResponse(f"<h1>Dashboard</h1>{body}")
