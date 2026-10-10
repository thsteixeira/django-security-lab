"""Test fixture for rules/mfa.yaml — paired to the rule by filename stem, so

    semgrep --test --config labs/post_15_mfa/rules/ labs/post_15_mfa/rules/

checks both rules against it.

It mirrors the lab's two dashboards and adds the shapes that decide whether a
policy rule like this is usable: the decorator called with arguments, the two
stacking orders of a correct view, @otp_required(if_configured=True) (optional
MFA, which must fire), a get_object_or_404() read, and a @login_required view
that reads a model the policy does NOT name, which must stay silent. The
functions marked todoruleid / todook document the rule's accepted blind spots.
Nothing here is imported at runtime.
"""

from django.contrib import auth
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group
from django.shortcuts import get_object_or_404
from django.views import View
from django_otp import login as otp_login
from django_otp.decorators import otp_required

from ..models import SensitiveRecord
from ..models import SensitiveRecord as SR


# --- sensitive-model-behind-password-only-gate --------------------------------


@login_required
def vulnerable_dashboard(request):
    """The lab's bug: a password-only session reaches the sensitive model."""
    # ruleid: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return list(SensitiveRecord.objects.filter(owner=request.user))


@otp_required
def secure_dashboard(request):
    """The lab's fix."""
    # ok: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return list(SensitiveRecord.objects.filter(owner=request.user))


@login_required
@otp_required
def secure_stacked(request):
    # ok: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return list(SensitiveRecord.objects.filter(owner=request.user))


@otp_required(login_url="/mfa/verify/")
@login_required
def secure_stacked_reversed_with_args(request):
    # ok: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return list(SensitiveRecord.objects.filter(owner=request.user))


@otp_required(if_configured=False)
def secure_if_configured_explicitly_false(request):
    # ok: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return list(SensitiveRecord.objects.filter(owner=request.user))


@otp_required(if_configured=True)
@login_required
def vulnerable_optional_mfa(request):
    """if_configured=True admits a user with no confirmed device: a user who
    never enrolled reaches the model on a password alone."""
    # ruleid: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return list(SensitiveRecord.objects.filter(owner=request.user))


@otp_required(if_configured=True)
def vulnerable_optional_mfa_alone(request):
    # ruleid: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return list(SensitiveRecord.objects.filter(owner=request.user))


@login_required(login_url="/accounts/login/")
def vulnerable_decorator_with_args(request):
    # ruleid: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return list(SensitiveRecord.objects.all())


@login_required
def vulnerable_get_object_or_404(request, pk):
    # ruleid: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return get_object_or_404(SensitiveRecord, pk=pk, owner=request.user)


@login_required
def profile_page(request):
    """Not every @login_required view needs a second factor. This model is not
    in the policy, so the view is correct and must stay silent."""
    # ok: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return list(Group.objects.filter(user=request.user))


def _records_for(user):
    return list(SensitiveRecord.objects.filter(owner=user))


@login_required
def vulnerable_via_helper(request):
    """Known limit: the read happens in a helper, outside the decorated body."""
    # todoruleid: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return _records_for(request.user)


class VulnerableDashboardView(LoginRequiredMixin, View):
    """Known limit: a class-based view has no decorator to key on."""

    def get(self, request):
        # todoruleid: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
        return list(SensitiveRecord.objects.filter(owner=request.user))


def undecorated_dashboard(request):
    """Known limit: wrapped in urls.py as login_required(undecorated_dashboard),
    so the function itself carries no decorator."""
    # todoruleid: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return list(SensitiveRecord.objects.filter(owner=request.user))


@login_required
def vulnerable_via_alias(request):
    """Known limit: the regex matches the model name as written, not an alias."""
    # todoruleid: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return list(SR.objects.filter(owner=request.user))


@login_required
def secure_hand_rolled_check(request):
    """Known false positive: verification enforced in the body, not by decorator."""
    if not request.user.is_verified():
        return None
    # todook: thiagoteixeira.django.security.mfa.sensitive-model-behind-password-only-gate
    return list(SensitiveRecord.objects.filter(owner=request.user))


# --- session-minted-without-second-factor -------------------------------------


def password_only_login(request, user):
    """The lab's side door: a full session from a password."""
    # ruleid: thiagoteixeira.django.security.mfa.session-minted-without-second-factor
    login(request, user)


def password_only_login_via_module(request, user):
    # ruleid: thiagoteixeira.django.security.mfa.session-minted-without-second-factor
    auth.login(request, user)


def verify_second_factor(request, device):
    """django_otp.login() records the verified device; it does not mint a session."""
    # ok: thiagoteixeira.django.security.mfa.session-minted-without-second-factor
    otp_login(request, device)


def hand_rolled_session(request, user):
    """Known limit: writes the session keys login() would, without calling it."""
    # todoruleid: thiagoteixeira.django.security.mfa.session-minted-without-second-factor
    request.session["_auth_user_id"] = str(user.pk)
