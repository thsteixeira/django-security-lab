from django.contrib.auth.models import User
from django.db import models


class ExportRecord(models.Model):
    """What a user's API export contains. One owner per row.

    Both export views serve the rows of exactly one user. They differ only in how
    they decide *which* user is asking: the vulnerable view believes whatever the
    token's payload says, the secure one believes it only after the signature
    checks out. bob's row holds the flag; nothing but a token that names bob can
    reach it.
    """

    owner = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="jwt_exports"
    )
    body = models.TextField()

    class Meta:
        db_table = "jwt_exportrecord"

    def __str__(self):
        return f"export_record(owner={self.owner_id})"
