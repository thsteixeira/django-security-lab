"""Runnable proof that ``fields = "__all__"`` lets a customer over-post columns
the order feature never meant to expose — forging the order's state and its
ownership — and that the explicit-allowlist + ``read_only_fields`` serializer
silently drops those over-posts while still writing the one field the customer
may change.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_10_mass_assignment

**What these assert.** Mass assignment here is a data-integrity failure on the
write path: the vulnerable serializer binds ``price``/``paid``/``status``/
``owner`` from the body, so a customer can mark their order free-and-paid (the
forged state the receipt view rewards with the flag) or reassign it to another
account (the write-side of IDOR). The fix is an explicit ``fields`` list with the
sensitive columns read-only — the over-posts are dropped, the request still
succeeds, and the legitimate ``quantity`` edit still lands.
"""
from decimal import Decimal

from django.contrib.auth.models import User
from rest_framework.test import APITestCase

from .models import Flag, Order
from .seed import FLAG


class MassAssignmentLabTests(APITestCase):
    def setUp(self):
        self.alice = User.objects.create_user("alice", password="labpass")
        self.bob = User.objects.create_user("bob", password="labpass")
        self.order = Order.objects.create(
            owner=self.alice,
            quantity=1,
            price=Decimal("49.90"),
            paid=False,
            status="pending",
        )
        Flag.objects.create(value=FLAG)

    def test_over_post_forges_order_state_on_vulnerable(self):
        # fields="__all__" binds price/paid/status from the body.
        resp = self.client.patch(
            f"/mass-assignment/vulnerable/orders/{self.order.pk}/",
            {"quantity": 1, "price": "0.00", "paid": True, "status": "shipped"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.order.refresh_from_db()
        self.assertEqual(self.order.price, Decimal("0.00"))  # over-posted
        self.assertTrue(self.order.paid)  # over-posted
        self.assertEqual(self.order.status, "shipped")  # over-posted
        # The forged free-and-paid state opens the receipt gate → the flag.
        receipt = self.client.get(f"/mass-assignment/receipt/{self.order.pk}/")
        self.assertEqual(receipt.data["receipt"], FLAG)

    def test_owner_reassignment_succeeds_on_vulnerable(self):
        # The write-side of IDOR: owner is a plain column under "__all__".
        resp = self.client.patch(
            f"/mass-assignment/vulnerable/orders/{self.order.pk}/",
            {"owner": self.bob.pk},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.order.refresh_from_db()
        self.assertEqual(self.order.owner, self.bob)

    def test_over_post_is_dropped_on_secure(self):
        # read_only_fields strips the over-posts; the request still returns 200.
        resp = self.client.patch(
            f"/mass-assignment/secure/orders/{self.order.pk}/",
            {"quantity": 2, "price": "0.00", "paid": True, "status": "shipped"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.order.refresh_from_db()
        self.assertEqual(self.order.quantity, 2)  # the allowed field WAS written
        self.assertEqual(self.order.price, Decimal("49.90"))  # over-post dropped
        self.assertFalse(self.order.paid)  # over-post dropped
        self.assertEqual(self.order.status, "pending")  # over-post dropped
        # No forged state, so the receipt view hands over nothing.
        receipt = self.client.get(f"/mass-assignment/receipt/{self.order.pk}/")
        self.assertIsNone(receipt.data["receipt"])

    def test_owner_reassignment_blocked_on_secure(self):
        # owner is read-only on the customer serializer — the reassignment is dropped.
        resp = self.client.patch(
            f"/mass-assignment/secure/orders/{self.order.pk}/",
            {"owner": self.bob.pk},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.order.refresh_from_db()
        self.assertEqual(self.order.owner, self.alice)
