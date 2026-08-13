"""SECURE order API — the fix for the mass-assignment sink in views_vulnerable.py.

Two changes, both in the serializer:

1. An explicit ``fields`` allowlist instead of ``"__all__"``. The serializer only
   knows about the columns named here; a new column added to ``Order`` next
   quarter is invisible until someone deliberately adds it (``fields`` fails
   closed, ``exclude`` would fail open).
2. ``read_only_fields`` for everything the customer may *see* but not *write*.
   ``quantity`` is the only writable field. An over-posted ``price``/``paid``/
   ``status``/``owner`` is stripped from ``validated_data`` before ``save()`` —
   the request still returns ``200``, but the tampered value never lands. That
   silent drop is the DRF behaviour worth internalising: the fix does not reject
   the request, it ignores the fields the client had no business writing.
"""
from rest_framework import permissions, serializers, viewsets

from .models import Order


class CustomerOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ["id", "quantity", "price", "paid", "status", "owner"]
        read_only_fields = ["id", "price", "paid", "status", "owner"]


class OrderViewSet(viewsets.ModelViewSet):
    """The customer may write ``quantity`` and nothing else."""

    queryset = Order.objects.all()
    serializer_class = CustomerOrderSerializer
    authentication_classes = []
    permission_classes = [permissions.AllowAny]
