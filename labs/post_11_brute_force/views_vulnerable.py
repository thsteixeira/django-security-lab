"""VULNERABLE login — a rate limit that *looks* like protection.

The view throttles by "client IP", but it resolves that IP from the first
`X-Forwarded-For` hop — a value the client controls (see `_throttle.py`). A naive
flood from one address is blocked after 5 tries; but an attacker who rotates the
forged header gets a brand-new bucket every request, from a single machine, and
walks the whole wordlist unthrottled. This is the post's signature finding: one
header turns the limiter off. It is also blind to distributed credential stuffing
for the same reason — the key answers "is this *source* noisy?", never "is this
*account* under attack?".

The secure twin (views_secure.py) keys the counter on the account instead.
"""
from django.contrib.auth import authenticate, login
from django.http import HttpResponse

from ._throttle import client_ip_from_forwarded_for, is_locked, register_failure


def login_view(request):
    if request.method != "POST":
        return HttpResponse(
            "<h1>Vulnerable login</h1><p>POST username &amp; password.</p>"
        )

    ip = client_ip_from_forwarded_for(request)
    key = f"bf:vuln:{ip}"  # DANGER: keyed on a client-controlled value
    if is_locked(key):
        return HttpResponse("rate limited\n", status=429)

    user = authenticate(
        request,
        username=request.POST.get("username", ""),
        password=request.POST.get("password", ""),
    )
    if user is None:
        register_failure(key)
        return HttpResponse("invalid credentials\n", status=401)

    login(request, user)
    return HttpResponse(f"logged in as {user.username}\n")
