"""Test fixture for rules/password_reset.yaml — paired to the rule by filename
stem, so `semgrep --test --config rules/ rules/` checks the rule against it.

It mirrors Lab 14's two confirm views and adds the two shapes that decide whether
a rule like this is usable rather than merely correct: the authenticated
"change your password" view, which calls set_password() with no token anywhere and
must stay silent, and a class-based confirm method, which must not. The last
function documents the rule's one known blind spot — a token pulled from the
request body rather than the URL — marked todoruleid because it is a false
negative the rule accepts on purpose.
"""

from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpResponse
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.views import View

from .models import ResetToken  # noqa: F401  (fixture only; never imported at runtime)


def _user(uidb64):
    return User.objects.get(pk=force_str(urlsafe_base64_decode(uidb64)))


# ruleid: thiagoteixeira.django.security.password-reset.reset-token-never-verified
def vulnerable_confirm(request, uidb64, token):
    """Looked up, scoped to a user, and never verified."""
    user = _user(uidb64)
    row = ResetToken.objects.filter(token=token, user=user).first()
    if row is None:
        return HttpResponse("invalid", status=400)
    user.set_password(request.POST["password"])
    user.save()
    return HttpResponse("ok")


def secure_confirm(request, uidb64, token):
    """One call, and the whole class of bug goes away."""
    user = _user(uidb64)
    if not default_token_generator.check_token(user, token):
        return HttpResponse("invalid or expired", status=400)
    # ok: thiagoteixeira.django.security.password-reset.reset-token-never-verified
    user.set_password(request.POST["password"])
    user.save()
    return HttpResponse("ok")


def secure_confirm_with_early_return(request, uidb64, token):
    """The guard-clause shape, to prove the rule is function-scoped.

    The registry's unvalidated-password rule fences with pattern-not-inside, which
    is scope-local and misses validation one call away (that false positive is
    documented in Lab 13). This rule clears on a check_token() anywhere in the
    function body, which is why an early return still counts.
    """
    user = _user(uidb64)
    verified = default_token_generator.check_token(user, token)
    if not verified:
        return HttpResponse("invalid or expired", status=400)
    # ok: thiagoteixeira.django.security.password-reset.reset-token-never-verified
    user.set_password(request.POST["password"])
    user.save()
    return HttpResponse("ok")


class VulnerableConfirmView(View):
    # ruleid: thiagoteixeira.django.security.password-reset.reset-token-never-verified
    def post(self, request, uidb64, token):
        user = _user(uidb64)
        if not ResetToken.objects.filter(token=token, user=user).exists():
            return HttpResponse("invalid", status=400)
        user.set_password(request.POST["password"])
        user.save()
        return HttpResponse("ok")


def change_own_password(request):
    """The shape that must never be flagged.

    An authenticated user changing their own password calls set_password() with no
    token in sight, and is correct. Keying the rule on a token-shaped parameter is
    what keeps this quiet — and is also the reason for the blind spot below.
    """
    user = request.user
    # ok: thiagoteixeira.django.security.password-reset.reset-token-never-verified
    user.set_password(request.POST["new_password"])
    user.save()
    return HttpResponse("ok")


def vulnerable_token_from_post_body(request):
    """Known limit: the same bug, read from the body, with no parameter to key on.

    This is exactly as broken as vulnerable_confirm above — an unverified token
    reaching set_password() — but the token arrives in the POST body, so the
    signature carries no hint and the rule stays silent. Accepted false negative:
    widening it to any set_password() near a variable called `token` would start
    firing on legitimate code, and confirming the token is really request-derived
    is interprocedural taint the community engine does not do.
    """
    user = _user(request.POST["uid"])
    token = request.POST["token"]
    if not ResetToken.objects.filter(token=token, user=user).exists():
        return HttpResponse("invalid", status=400)
    # todoruleid: thiagoteixeira.django.security.password-reset.reset-token-never-verified
    user.set_password(request.POST["password"])
    user.save()
    return HttpResponse("ok")
