"""SECURE registration — the same flow, with one call in the right place.

Three things are load-bearing and all three are easy to get subtly wrong:

1. ``validate_password()`` runs **before** ``set_password()``, so a rejected
   password never reaches the hasher or the database. Validating afterwards
   raises the exception after the weak password is already committed.
2. The **user object is passed**. ``UserAttributeSimilarityValidator.validate()``
   opens with ``if not user: return`` — call it as ``validate_password(password)``
   and that validator silently does nothing, while the code still reads like a
   security control. The instance may be unsaved; the validator only reads
   attributes, which is exactly how ``createsuperuser`` uses it.
3. The ``ValidationError`` is **surfaced**, not logged. ``exc.messages`` carries
   the same strings Django's own auth forms show.

Where a ``ModelForm`` fits, the better answer is to not write this at all:
``BaseUserCreationForm``/``SetPasswordForm`` already call the validator via
``SetPasswordMixin.validate_password_for_user()``. Hand-rolling is for the paths
a form does not cover — DRF serializers, invite flows, management commands.
"""

from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .policy import get_policy


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

    try:
        # Before the write, with the (still unsaved) user.
        validate_password(password, user, password_validators=get_policy())
    except ValidationError as exc:
        return HttpResponse(
            "password rejected:\n" + "".join(f"  - {m}\n" for m in exc.messages),
            status=400,
        )

    user.set_password(password)
    user.save()

    return HttpResponse(
        f"registered {user.username} (password validated)\n", status=201
    )
