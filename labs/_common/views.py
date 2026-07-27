"""Shared login/logout endpoints for the authenticated labs (B1).

Session-cookie auth, so a learner can log in from the command line and reuse the
session across the vulnerable/secure requests:

    curl -c jar.txt -d 'username=alice&password=labpass' localhost:8000/accounts/login/
    curl -b jar.txt localhost:8000/idor/vulnerable/<bob_note_pk>/

`login_view` is `@csrf_exempt` so the single POST above is enough. Global CSRF is
off anyway (see settings.py); the exemption is explicit so this endpoint keeps
working unchanged even inside the CSRF lab, whose scope is its *own* views.
"""

from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST


@csrf_exempt
@require_POST
def login_view(request):
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    user = authenticate(request, username=username, password=password)
    if user is None:
        return HttpResponse("invalid credentials\n", status=401)
    login(request, user)
    return HttpResponse(f"logged in as {user.username}\n")


@csrf_exempt
def logout_view(request):
    logout(request)
    return HttpResponse("logged out\n")
