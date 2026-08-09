from django.contrib.auth.models import User
from django.db import models


class Account(models.Model):
    """A per-user account holding a transferable value.

    The flag is that value, so a successful cross-site forgery is visible in the
    database (the flag *moves* from the victim to the attacker), not merely in a
    status code. `user` is `editable=False` — it is set at seed time, never from
    a request.
    """

    user = models.OneToOneField(User, on_delete=models.CASCADE, editable=False)
    holdings = models.CharField(max_length=200, blank=True)

    class Meta:
        db_table = "csrf_account"

    def __str__(self):
        return f"{self.user.username}: {self.holdings!r}"
