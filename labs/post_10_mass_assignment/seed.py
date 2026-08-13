"""Sample data and the CTF flag for Lab 10. Run via `manage.py seed_labs`.

Seeds one pending order owned by ``alice`` (price 49.90, unpaid, status pending)
and the receipt flag. Idempotent — reseeding wipes any state a previous exploit
forged and recreates the clean order. The seed message includes the order's pk
so the README curl walkthrough can target it.
"""
from decimal import Decimal

from labs._common.users import seed_users

from .models import Flag, Order

FLAG = "FLAG{mass_assignment_over_posted_order_state}"


def seed():
    users = seed_users()

    Order.objects.all().delete()
    order = Order.objects.create(
        owner=users["alice"],
        quantity=1,
        price=Decimal("49.90"),
        paid=False,
        status="pending",
    )

    Flag.objects.all().delete()
    Flag.objects.create(value=FLAG)

    return (
        f"seeded a pending order pk={order.pk} (owner=alice, price=49.90, unpaid) "
        "+ the receipt flag"
    )
