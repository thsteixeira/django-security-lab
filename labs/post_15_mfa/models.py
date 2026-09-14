from django.contrib.auth.models import User
from django.db import models


class SensitiveRecord(models.Model):
    """What the second factor is supposed to be protecting.

    One record, one owner, and the flag inside it. Both dashboards serve exactly
    this row — they differ only in the decorator above them, which is the whole
    point of the lab: the resource is identical, the gate is not.
    """

    owner = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="mfa_records"
    )
    body = models.TextField()

    class Meta:
        db_table = "mfa_sensitiverecord"

    def __str__(self):
        return f"sensitive_record(owner={self.owner_id})"
