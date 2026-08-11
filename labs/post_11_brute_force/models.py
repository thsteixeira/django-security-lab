from django.contrib.auth.models import User
from django.db import models


class Note(models.Model):
    """The victim's private note holds the flag. Reading it requires an
    authenticated session belonging to the victim — so cracking the password
    yields something concrete (the flag), not just a 200."""

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="bf_notes")
    body = models.TextField()

    class Meta:
        db_table = "bruteforce_note"

    def __str__(self):
        return f"note(owner={self.owner_id})"
