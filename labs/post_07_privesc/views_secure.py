"""SECURE profile edit — the same feature, with an explicit field allowlist.

The form lists exactly `["display_name", "bio"]`. `role` is not a field on the
form, so a `role=staff` value in the POST is silently dropped before `save()` —
the member stays a member no matter what they submit. Everything else about the
view is identical to the vulnerable twin.

The invariant: enumerate the fields the client may write; never `"__all__"` on a
model that carries a privilege field.
"""
from django import forms
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.utils.html import escape

from .models import Profile


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ["display_name", "bio"]  # allowlist: `role` is unreachable


@login_required
def edit_profile(request):
    profile = request.user.profile
    saved = False
    if request.method == "POST":
        # The allowlist form has no `role` field, so `role` in the POST is ignored.
        form = ProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            saved = True
    fresh = Profile.objects.get(pk=profile.pk)
    return HttpResponse(
        "<h1>Secure profile edit</h1>"
        f"<p>user <strong>{escape(request.user.username)}</strong> — "
        f"role <strong>{escape(fresh.role)}</strong>, "
        f"display_name <strong>{escape(fresh.display_name)}</strong>"
        f"{' (saved)' if saved else ''}</p>"
    )
