from django.contrib.auth.models import User
from django.db import models


class Secret(models.Model):
    """The victim's private data holds the flag. Reading it requires an
    authenticated session belonging to the victim — so guessing the victim's
    weak password in one attempt yields the flag, not just a 200."""

    owner = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="weak_password_secrets"
    )
    body = models.TextField()

    class Meta:
        db_table = "weakpasswords_secret"

    def __str__(self):
        return f"secret(owner={self.owner_id})"
