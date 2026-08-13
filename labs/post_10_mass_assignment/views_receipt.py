"""The flag gate — shared by both variants, not itself vulnerable.

``receipt/<pk>/`` reads an order and returns the CTF flag only if the order is in
the forged *free-and-paid* state (``paid=True`` and ``price=0``). Because the
legitimate flow never sets those fields from the request, an order can only reach
that state by over-posting through the vulnerable serializer. So the receipt is
an honest oracle: it hands over the flag exactly when the integrity of the order
record has been broken, and stays silent otherwise.
"""
from decimal import Decimal

from django.shortcuts import get_object_or_404
from rest_framework import permissions
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.response import Response

from .models import Flag, Order


@api_view(["GET"])
@authentication_classes([])
@permission_classes([permissions.AllowAny])
def receipt(request, pk):
    order = get_object_or_404(Order, pk=pk)
    forged = order.paid and order.price == Decimal("0")
    if forged:
        flag = Flag.objects.values_list("value", flat=True).first()
        return Response(
            {
                "receipt": flag,
                "detail": "Order is paid AND free — a state the customer flow "
                "cannot produce. Its integrity was forged by over-posting.",
                "order": {"price": str(order.price), "paid": order.paid},
            }
        )
    return Response(
        {
            "receipt": None,
            "detail": "Nothing forged: this order is not both paid and free.",
            "order": {"price": str(order.price), "paid": order.paid},
        }
    )
