"""VULNERABLE password reset — three flaws in eleven lines of logic.

The flow is correct in every way a code review usually checks. It generates a
random token from ``uuid4``, stores it server-side, scopes it to one user,
records when it was issued and when it was used, and never puts the password in
an email. It looks careful, because it is careful about the wrong things.

1. **The token never expires.** ``ResetToken.created`` is written and never read.
   A link mailed last year still works today.
2. **The token is never retired.** ``used_at`` is written by this very view and
   never read either, so one token resets the password an unlimited number of
   times. This is the flaw that makes a *leaked* link permanent rather than
   merely embarrassing: reset links reach proxy logs, browser history, ``Referer``
   headers on the confirmation page, and mailbox backups.
3. **The reset link's host comes from the request.**
   ``request.build_absolute_uri()`` resolves the host by asking ``request``,
   which asks the client. Change the ``Host`` header and you change the domain in
   an email your server sends to someone else's inbox.

And one more, in the request half: the 404 on an unknown address turns this
endpoint into an account oracle — POST an email, read the status code, learn
whether that person has an account here.

``views_secure.py`` is the same flow with Django's own token generator.
"""

import uuid

from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.http import HttpResponse
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .helpers import user_from_uidb64
from .models import ResetToken


@csrf_exempt
@require_POST
def request_reset(request):
    email = request.POST.get("email", "")
    if not email:
        return HttpResponse("email required\n", status=400)

    try:
        user = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        # DANGER: the answer differs, so the endpoint answers a question nobody
        # asked it — "does this person have an account here?"
        return HttpResponse("no account with that email\n", status=404)

    row = ResetToken.objects.create(user=user, token=str(uuid.uuid4()))
    path = reverse(
        "pr_vulnerable_confirm",
        kwargs={
            "uidb64": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": row.token,
        },
    )
    # DANGER: the host in this URL is whatever the client said it was.
    link = request.build_absolute_uri(path)
    send_mail(
        "Reset your password",
        f"Use this link to reset your password:\n\n{link}\n",
        "noreply@lab.test",
        [user.email],
    )
    return HttpResponse("reset email sent\n")


@csrf_exempt
@require_POST
def confirm(request, uidb64, token):
    user = user_from_uidb64(uidb64)
    row = ResetToken.objects.filter(token=token).first()
    if user is None or row is None or row.user_id != user.pk:
        return HttpResponse("invalid reset link\n", status=400)

    # DANGER: nothing between here and the write consults row.created (age) or
    # row.used_at (already spent). Both columns exist. Both are populated. No
    # branch reads either one.

    new_password = request.POST.get("password", "")
    if not new_password:
        return HttpResponse("password required\n", status=400)

    user.set_password(new_password)
    user.save()

    row.used_at = timezone.now()
    row.save(update_fields=["used_at"])

    return HttpResponse(f"password updated for {user.username}\n")
