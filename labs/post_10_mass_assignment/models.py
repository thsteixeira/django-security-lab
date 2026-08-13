from decimal import Decimal

from django.contrib.auth.models import User
from django.db import models


class Order(models.Model):
    """A customer order — the running example from the post.

    Exactly one column is legitimately customer-writable: ``quantity``. The rest
    are owned by the server or the workflow:

    * ``price``  — set from the catalogue, never from the request.
    * ``paid``   — flipped by the payment webhook, not the customer.
    * ``status`` — advanced by fulfilment (``pending`` → ``shipped`` → …).
    * ``owner``  — the account the order belongs to.

    Mass assignment is what happens when a serializer binds *all* of these from
    the request body. The vulnerable view's ``fields = "__all__"`` does exactly
    that; the secure view lists ``quantity`` and marks the rest read-only.
    """

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="orders")
    quantity = models.PositiveIntegerField(default=1)
    price = models.DecimalField(max_digits=8, decimal_places=2, default=Decimal("49.90"))
    paid = models.BooleanField(default=False)
    status = models.CharField(max_length=20, default="pending")

    class Meta:
        db_table = "massassign_order"

    def __str__(self):
        return f"Order #{self.pk} (qty={self.quantity}, price={self.price}, paid={self.paid})"


class Flag(models.Model):
    """The CTF secret, handed out by the receipt view only for an order in the
    forged *free-and-paid* state (``paid=True`` and ``price=0``).

    The legitimate flow can never reach that state — ``price`` comes from the
    catalogue and ``paid`` from the payment webhook, and neither is
    client-writable — so an order that is both paid and free could only have got
    there by over-posting. Capturing the flag *is* the integrity violation.
    """

    value = models.CharField(max_length=200)

    class Meta:
        db_table = "massassign_flag"

    def __str__(self):
        return self.value
