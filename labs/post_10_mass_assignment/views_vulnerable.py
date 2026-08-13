"""VULNERABLE order API — do NOT copy this into real code.

The serializer's ``Meta.fields = "__all__"`` binds *every* column on ``Order``
from the request body, so a customer PATCHing their order can also send
``price``, ``paid``, ``status``, and ``owner`` — none of which the feature ever
meant to expose. DRF validates each value against its field type, ``save()``
writes the lot, and the request returns ``200``. Over-posting
``{"price": "0.00", "paid": true}`` leaves the order *free and paid*, a state the
legitimate flow can never produce; the ``receipt/<pk>/`` view then hands over the
flag for exactly that forged state.

The serializer is defined inline (rather than in a shared ``serializers.py``) so
the vulnerable and secure variants live in their own files — the per-file layout
the CI custom-rule scan-assert relies on. The fix (``views_secure.py``) changes
one thing: an explicit ``fields`` allowlist plus ``read_only_fields``.
"""
from rest_framework import permissions, serializers, viewsets

from .models import Order


class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = "__all__"  # DANGER: price, paid, status, owner are all writable


class OrderViewSet(viewsets.ModelViewSet):
    """Every ``Order`` column is writable from the API — mass assignment."""

    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    # The lab is intentionally open: no auth/CSRF friction so a single curl
    # PATCH reproduces the bug. The vulnerability is the field binding, not the
    # access control.
    authentication_classes = []
    permission_classes = [permissions.AllowAny]
