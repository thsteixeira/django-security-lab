"""SECURE too — the idiomatic Django shape, where a Form does the validating.

This is the architecture most real Django applications actually use, and the one
the post recommends over hand-rolling: the form owns validation (``clean_*``
raises ``ValidationError``, which Django turns into form errors), and the view
runs only once ``is_valid()`` has passed. ``django.contrib.auth.forms``'s own
``SetPasswordForm`` and ``BaseUserCreationForm`` are built exactly this way — they
call ``validate_password(password, user)`` from
``SetPasswordMixin.validate_password_for_user()``.

It is included in the lab for a second reason: **Semgrep's
`python.django.security.audit.unvalidated-password` flags this file.** The rule
fences `$MODEL.set_password($X)` with `pattern-not-inside` clauses that look for a
`validate_password(...)` call *in the same lexical scope*. Here the validation
lives in `RegistrationForm.clean_password()` and the write lives in `register()` —
two different scopes, one function call apart — so the rule cannot see the guard
and reports a false positive on code that is, in fact, correctly validated.

That is the honest limitation of a `confidence: LOW` audit rule, and it is worth
knowing before you run it across a real codebase: the *more* idiomatic your Django
is, the more likely this rule is to be wrong about it. See scans/README.md.
"""

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .policy import get_policy


class RegistrationForm(forms.Form):
    """Validation lives here, next to the field it belongs to."""

    username = forms.CharField(max_length=150)
    password = forms.CharField()

    def clean_username(self):
        username = self.cleaned_data["username"]
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("username taken")
        return username

    def clean_password(self):
        password = self.cleaned_data["password"]
        # The user is unsaved and built from the data cleaned so far, so
        # UserAttributeSimilarityValidator still has a username to compare against.
        validate_password(
            password,
            User(username=self.data.get("username", "")),
            password_validators=get_policy(),
        )
        return password


@csrf_exempt
@require_POST
def register(request):
    form = RegistrationForm(request.POST)
    if not form.is_valid():
        errors = "".join(
            f"  - {message}\n"
            for messages in form.errors.values()
            for message in messages
        )
        return HttpResponse(f"password rejected:\n{errors}", status=400)

    user = User(username=form.cleaned_data["username"])
    # Reached only when the form validated. Semgrep flags this line anyway — the
    # guard is one scope away, and the rule only looks in this one.
    user.set_password(form.cleaned_data["password"])
    user.save()

    return HttpResponse(
        f"registered {user.username} (validated in the form)\n", status=201
    )
