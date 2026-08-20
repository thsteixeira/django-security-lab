from django.contrib.auth.models import User
from django.db import models


class Secret(models.Model):
    """The victim's private data holds the flag. Reading it requires an
    authenticated session belonging to the victim — so riding the victim's
    fixated (never-rotated) session yields the flag, not just a 200."""

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="secrets")
    body = models.TextField()

    class Meta:
        db_table = "sessionfixation_secret"

    def __str__(self):
        return f"secret(owner={self.owner_id})"
