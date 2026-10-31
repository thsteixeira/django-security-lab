"""SECURE — the same sign-up, with the password stored by ``set_password()``.

``set_password()`` takes the hasher, the salt and the iteration count from Django:
the first entry of ``PASSWORD_HASHERS`` (PBKDF2-SHA256, 1,000,000 iterations on
Django 5.2), a fresh 22-character salt for every row, and a stored value that
records all three, so the same password never produces the same row twice.

There is no secure login view: Django's ``ModelBackend``, behind the shared
``/accounts/login/``, checks what ``set_password()`` writes, so the custom backend
the vulnerable twin needs has nothing left to do and goes.

Password *strength* is not this lab's subject (that is Lab 13), so this view
validates nothing; it accepts the same weak password the vulnerable view does, and
the difference is entirely in what a leaked copy of the row costs to crack.
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
    email = request.POST.get("email", "")
    if not username or not password:
        return HttpResponse("username and password required\n", status=400)
    if User.objects.filter(username=username).exists():
        return HttpResponse("username taken\n", status=409)

    user = User(username=username, email=email)
    user.set_password(password)
    user.save()

    return HttpResponse(f"registered {user.username} (PBKDF2, salted)\n", status=201)
