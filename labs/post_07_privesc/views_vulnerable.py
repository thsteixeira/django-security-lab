"""VULNERABLE profile edit — do NOT copy this into real code.

The form is a `ModelForm` with `Meta.fields = "__all__"`, so it binds every
editable field on `Profile` from the POST — including `role`, the privilege
field the profile page never meant to expose. A regular member submits the form
with an extra `role=staff` field and promotes themselves; the next request to the
staff-gated view returns the flag. The ORM makes no distinction between
`display_name` and `role`: both are columns, both are in `"__all__"`.

The form is defined inline (rather than in a shared forms.py) so the vulnerable
and secure variants live in their own files — the per-file layout the CI
scan-assert relies on. The fix (views_secure.py) changes one thing: an explicit
`fields` allowlist.
"""
from django import forms
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.utils.html import escape

from .models import Profile


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = "__all__"  # DANGER: exposes `role` to mass assignment


@login_required
def edit_profile(request):
    profile = request.user.profile
    saved = False
    if request.method == "POST":
        # DANGER: fields="__all__" means `role` in the POST is written too.
        form = ProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            saved = True
    role = Profile.objects.get(pk=profile.pk).role
    return HttpResponse(
        "<h1>Vulnerable profile edit</h1>"
        f"<p>user <strong>{escape(request.user.username)}</strong> — "
        f"role <strong>{escape(role)}</strong>{' (saved)' if saved else ''}</p>"
        "<p>POST display_name/bio here — the form also accepts <code>role</code>.</p>"
    )
