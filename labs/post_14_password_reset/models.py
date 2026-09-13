from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class ResetToken(models.Model):
    """The hand-rolled reset token: a random string in a row, and nothing else.

    Every field a reviewer would look for is here. ``created`` is recorded, so
    the flow *could* expire. ``used_at`` is recorded, so it *could* be single-use.
    Both columns are written faithfully by ``views_vulnerable.confirm``. Neither
    is ever read by a branch that refuses anything.

    That is what makes this the realistic shape of the bug rather than a straw
    man: the data model is not missing anything. The check is.
    """

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="lab_reset_tokens"
    )
    token = models.CharField(max_length=36, unique=True)
    created = models.DateTimeField(default=timezone.now)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "passwordreset_token"

    def __str__(self):
        return f"reset_token(user={self.user_id}, used={self.used_at is not None})"


class VaultItem(models.Model):
    """What owning the account is actually worth.

    A reset that succeeds only prints "password updated"; that proves nothing on
    its own. The flag lives behind an authenticated, ``request.user``-scoped read,
    so capturing it means the attacker completed the takeover — reset the
    password, logged in, and read data that was never theirs.
    """

    owner = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="lab_vault_items"
    )
    body = models.TextField()

    class Meta:
        db_table = "passwordreset_vaultitem"

    def __str__(self):
        return f"vault_item(owner={self.owner_id})"
