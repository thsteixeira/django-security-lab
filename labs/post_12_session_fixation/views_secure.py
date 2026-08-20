"""SECURE login — the same flow through ``django.contrib.auth.login()``, which
calls ``cycle_key()``: a brand-new random session id is issued on the privilege
change, so any id the attacker fixed beforehand is orphaned (it was never
promoted) and the victim's browser now carries an id the attacker has never seen.
One line closes the whole fixation surface."""
from django.contrib.auth import authenticate, login
from django.http import HttpResponse


def login_view(request):
    if request.method != "POST":
        return HttpResponse(
            "<h1>Secure login</h1><p>POST username &amp; password.</p>"
        )

    user = authenticate(
        request,
        username=request.POST.get("username", ""),
        password=request.POST.get("password", ""),
    )
    if user is None:
        return HttpResponse("invalid credentials\n", status=401)

    login(request, user)  # cycle_key(): new random session id, data preserved
    return HttpResponse(f"logged in as {user.username} (session rotated)\n")
