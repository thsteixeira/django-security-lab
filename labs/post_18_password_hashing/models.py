from django.contrib.auth.models import User
from django.db import models


class Note(models.Model):
    """A legacy account's private note. carla's holds the flag, and reading it takes
    a session as carla — so cracking her leaked hash yields the flag, not just a
    password."""

    owner = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="password_hashing_notes"
    )
    body = models.TextField()

    class Meta:
        db_table = "passwordhashing_note"

    def __str__(self):
        return f"note(owner={self.owner_id})"
