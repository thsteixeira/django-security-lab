from django.contrib.auth.models import User
from django.db import models


class Profile(models.Model):
    """A per-user profile carrying a privilege field, `role`.

    `user` is `editable=False` on purpose: it keeps the OneToOne link out of a
    `ModelForm(fields="__all__")` (non-editable fields are excluded), so the
    vulnerable form's footgun is `role` alone and a minimal `role=staff` POST
    still validates — the FK is not a required form field. `role` is a plain
    CharField the profile-edit feature was never meant to expose.
    """

    user = models.OneToOneField(User, on_delete=models.CASCADE, editable=False)
    display_name = models.CharField(max_length=100, blank=True)
    bio = models.TextField(blank=True)
    role = models.CharField(max_length=20, default="member")  # "member" | "staff"

    class Meta:
        db_table = "privesc_profile"

    def __str__(self):
        return f"{self.user.username} ({self.role})"


class Flag(models.Model):
    """The CTF secret, served only by the staff-gated view. Capturing it *is*
    the escalation: it sits behind `profile.role == "staff"`."""

    value = models.CharField(max_length=200)

    class Meta:
        db_table = "privesc_flag"

    def __str__(self):
        return self.value
