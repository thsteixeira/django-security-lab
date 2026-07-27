from django.contrib.auth.models import User
from django.db import models


class Note(models.Model):
    """A per-user note. The flag lives in the body of a note owned by *bob*.

    The security boundary under study is **ownership**, so the flag sits behind
    it rather than in a separate table: capturing it means reading a record that
    belongs to another user. Each seeded user owns notes; the vulnerable view
    hands over any note by primary key, the secure view only the requester's.
    """

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notes")
    title = models.CharField(max_length=200)
    body = models.TextField()

    class Meta:
        db_table = "idor_note"

    def __str__(self):
        return f"{self.title} (owner={self.owner_id})"
