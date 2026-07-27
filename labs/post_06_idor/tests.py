"""Runnable proof that the vulnerable view hands over another user's note by PK,
that the secure view scopes the lookup to the owner and returns an
indistinguishable 404, and that the fix does not break the owner's own access.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_06_idor

**What these assert.** IDOR is missing *object-level* authorisation: being
authenticated (alice is logged in) is not being authorised (the note is bob's).
The exploit is reading bob's note by its PK; the fix is that the same PK returns
a 404 for alice while her own note still resolves.
"""

from django.contrib.auth.models import User
from django.test import Client, TestCase

from .models import Note
from .seed import FLAG


class IdorLabTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user("alice", password="labpass")
        self.bob = User.objects.create_user("bob", password="labpass")
        self.alice_note = Note.objects.create(
            owner=self.alice, title="Alice's list", body="milk, eggs"
        )
        self.bob_note = Note.objects.create(
            owner=self.bob, title="Bob's private note", body=f"secret: {FLAG}"
        )
        self.client = Client()
        self.client.force_login(self.alice)

    def test_exploit_succeeds_on_vulnerable_view(self):
        # Alice reaches Bob's note by PK — no ownership check stands in the way.
        resp = self.client.get(f"/idor/vulnerable/{self.bob_note.pk}/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(FLAG, resp.content.decode())

    def test_exploit_is_blocked_on_secure_view(self):
        # The same request is scoped to the requester: Bob's note is not in
        # Alice's queryset, so the response is a 404 that leaks nothing.
        resp = self.client.get(f"/idor/secure/{self.bob_note.pk}/")
        self.assertEqual(resp.status_code, 404)
        self.assertNotIn(FLAG, resp.content.decode())

    def test_owner_still_reaches_their_own_note_on_secure_view(self):
        # The fix scopes by owner without breaking legitimate access: Alice still
        # reads her own note on the secure view.
        resp = self.client.get(f"/idor/secure/{self.alice_note.pk}/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("milk, eggs", resp.content.decode())
