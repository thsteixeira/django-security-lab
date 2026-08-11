"""SECURE login — count failures per *account*, not per source.

The only change that matters: the lockout key is the **username** being tried,
not the caller's address. After 5 failures for an account it is locked for the
window regardless of how many IPs (or forged `X-Forwarded-For` headers) the
attacker rotates through — the control the vulnerable twin structurally cannot
have. A correct password on a not-yet-locked account still works, so legitimate
users are not punished.

In production this is what `django-axes` does (per-account counting, in a shared
store); the README points there. Here it is a few lines so the *keying* — the
whole lesson — is visible.
"""
from django.contrib.auth import authenticate, login
from django.http import HttpResponse

from ._throttle import is_locked, register_failure


def login_view(request):
    if request.method != "POST":
        return HttpResponse(
            "<h1>Secure login</h1><p>POST username &amp; password.</p>"
        )

    username = request.POST.get("username", "")
    key = f"bf:secure:{username.lower()}"  # keyed on the ACCOUNT, not the source
    if is_locked(key):
        return HttpResponse("account locked — too many failures\n", status=403)

    user = authenticate(
        request, username=username, password=request.POST.get("password", "")
    )
    if user is None:
        register_failure(key)
        return HttpResponse("invalid credentials\n", status=401)

    login(request, user)
    return HttpResponse(f"logged in as {user.username}\n")
