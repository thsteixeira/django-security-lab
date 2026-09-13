"""SECURE password reset — Django's token generator, and a host it already knows.

The fix is not a longer random string. ``uuid4`` is already unguessable; length
was never the problem. The problem is that a stored random string carries no
information about *when* it was issued or *whether the account has moved on since*,
so every check you want has to be written, and remembered, by hand.

``PasswordResetTokenGenerator`` makes the token carry that state instead of the
database. Its hash input is the user's pk, the **password hash**, ``last_login``,
the user's email, and a timestamp, all HMAC'd with ``SECRET_KEY``. Three
properties fall out of that one design, none of which needs a branch here:

* it **expires**, because the timestamp is inside the hash and ``check_token``
  compares it against ``PASSWORD_RESET_TIMEOUT`` (3 days by default);
* it **self-retires on use**, because completing a reset changes
  ``user.password``, which changes the hash input, which makes every token issued
  against the old password stop verifying — including the one just used;
* it **self-retires on login**, because ``last_login`` is in the hash too.

So the ``used_at`` bookkeeping the vulnerable view maintains and ignores is not
reimplemented here correctly — it is *not needed*, which is a stronger outcome
than remembering to check it.

The second change is ``build_reset_link()``: the host comes from configuration,
not from ``request``. The third is the response — identical whether or not the
address matched an account, so the endpoint stops answering questions about who
has an account here.
"""

from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.http import HttpResponse
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .helpers import build_reset_link, user_from_uidb64

# One string, whether or not the address matched. See the README on the timing
# side channel this does not close.
UNIFORM_REPLY = "if an account exists for that address, a reset link has been sent\n"


@csrf_exempt
@require_POST
def request_reset(request):
    email = request.POST.get("email", "")
    if not email:
        return HttpResponse("email required\n", status=400)

    user = User.objects.filter(email__iexact=email).first()
    if user is not None:
        path = reverse(
            "pr_secure_confirm",
            kwargs={
                "uidb64": urlsafe_base64_encode(force_bytes(user.pk)),
                "token": default_token_generator.make_token(user),
            },
        )
        # Configuration, not request.get_host(). A poisoned Host header changes
        # nothing about this URL.
        link = build_reset_link(path)
        send_mail(
            "Reset your password",
            f"Use this link to reset your password:\n\n{link}\n",
            "noreply@lab.test",
            [user.email],
        )

    # Same body, same status, both ways.
    return HttpResponse(UNIFORM_REPLY)


@csrf_exempt
@require_POST
def confirm(request, uidb64, token):
    user = user_from_uidb64(uidb64)
    # One call covers signature, age, prior use, and an intervening login.
    if user is None or not default_token_generator.check_token(user, token):
        return HttpResponse("invalid or expired reset link\n", status=400)

    new_password = request.POST.get("password", "")
    if not new_password:
        return HttpResponse("password required\n", status=400)

    user.set_password(new_password)
    user.save()
    # No bookkeeping row to retire: the save above already invalidated this
    # token, because user.password is part of what the token hashes.

    return HttpResponse(f"password updated for {user.username}\n")
