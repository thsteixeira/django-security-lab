"""VULNERABLE registration — hashes the password correctly and never validates it.

``set_password()`` does its job perfectly: it runs the configured hasher, salts,
and writes a hash the rest of Django understands. That competence is exactly what
makes the line look finished. Validation is a *separate subsystem with a separate
entry point*, and nothing in the model layer reaches for it — so this view ignores
``AUTH_PASSWORD_VALIDATORS`` entirely. The project has a password policy; this
code path simply never asks what it is.

``User.objects.create_user(username=..., password=...)`` has the identical gap for
the identical reason: its ``_create_user_object()`` calls ``make_password()``
directly.

The secure twin (``views_secure.py``) adds one call, in the right place, with both
arguments.
"""

from django.contrib.auth.models import User
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST


@csrf_exempt
@require_POST
def register(request):
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    if not username or not password:
        return HttpResponse("username and password required\n", status=400)
    if User.objects.filter(username=username).exists():
        return HttpResponse("username taken\n", status=409)

    user = User(username=username, email=request.POST.get("email", ""))
    # DANGER: hashes it, does not validate it. No consultation of
    # AUTH_PASSWORD_VALIDATORS happens anywhere in this request.
    user.set_password(password)
    user.save()

    return HttpResponse(
        f"registered {user.username} (password NOT validated)\n", status=201
    )
