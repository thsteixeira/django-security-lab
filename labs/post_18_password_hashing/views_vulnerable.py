"""VULNERABLE — a password column hashed by hand, and the login that has to match it.

The usual origin is a migration from an older system: the old database stored
SHA-1 hex digests, the Django project imported them, and to keep those passwords
working someone wrote a backend that compares SHA-1s (``backends.py``). Then, for
consistency, new sign-ups were hashed the same way. Every row this view writes is
fast to compute and unsalted, so a leaked table is cracked in one pass of a
wordlist — for every account at once.

Nothing here is reachable by an attacker as a *request*: the attack is offline,
against a copy of the table (``manage.py dump_password_table``, then ``crack.py``).
These views only decide what that copy contains, and how a cracked password is
used afterwards.

The secure twin (``views_secure.py``) replaces one line with ``set_password()``
and has no login of its own: Django's ``ModelBackend``, behind the shared
``/accounts/login/``, checks what ``set_password()`` writes.
"""

import hashlib

from django.contrib.auth import login as auth_login
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .backends import SHA1Backend


@csrf_exempt
@require_POST
def register(request):
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    email = request.POST.get("email", "")
    if not username or not password:
        return HttpResponse("username and password required\n", status=400)
    if User.objects.filter(username=username).exists():
        return HttpResponse("username taken\n", status=409)

    user = User(username=username, email=email)
    # DANGER: a fast, unsalted digest. The same password gives the same 40
    # characters in every row, and in every other table that ever used SHA-1.
    user.password = hashlib.sha1(password.encode()).hexdigest()
    user.save()

    return HttpResponse(f"registered {user.username} (SHA-1, no salt)\n", status=201)


@csrf_exempt
@require_POST
def login(request):
    user = SHA1Backend().authenticate(
        request,
        username=request.POST.get("username", ""),
        password=request.POST.get("password", ""),
    )
    if user is None:
        return HttpResponse("invalid credentials\n", status=401)
    # The session records ModelBackend, which reloads the user by primary key on
    # the next request; SHA1Backend is not in AUTHENTICATION_BACKENDS (see
    # backends.py), so naming it here would sign the session straight out again.
    auth_login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    return HttpResponse(f"logged in as {user.username}\n")
