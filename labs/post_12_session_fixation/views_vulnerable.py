"""VULNERABLE login — authenticates by writing the auth keys to the session by
hand, so the pre-login session id is NEVER rotated (session fixation).

This reproduces exactly what ``django.contrib.auth.login()`` writes to the
session — ``_auth_user_id``, the backend path, and the session-auth hash (all
three are required for ``request.user`` to resolve on the next request) — but
leaves out the one thing you cannot see it do: ``cycle_key()``. Because the key
is never rotated, a session id an attacker fixed onto the victim *before* login
is promoted, in place, to the victim's authenticated session. The attacker, who
chose that id, now rides it.

The secure twin (``views_secure.py``) changes one thing: it calls ``auth.login()``.
"""
from django.contrib.auth import authenticate
from django.http import HttpResponse


def login_view(request):
    if request.method != "POST":
        return HttpResponse(
            "<h1>Vulnerable login</h1><p>POST username &amp; password.</p>"
        )

    user = authenticate(
        request,
        username=request.POST.get("username", ""),
        password=request.POST.get("password", ""),
    )
    if user is None:
        return HttpResponse("invalid credentials\n", status=401)

    # DANGER: these are the writes login() makes — but NOT its cycle_key()
    # rotation. The session id the browser arrived with is promoted in place.
    request.session["_auth_user_id"] = str(user.pk)
    request.session["_auth_user_backend"] = "django.contrib.auth.backends.ModelBackend"
    request.session["_auth_user_hash"] = user.get_session_auth_hash()
    return HttpResponse(f"logged in as {user.username} (session NOT rotated)\n")
