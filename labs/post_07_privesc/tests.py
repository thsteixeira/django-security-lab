"""Runnable proof that the vulnerable form lets a member write its own `role`
and reach the staff-gated flag, that the allowlist form drops the injected
`role`, and that the fix still saves the fields it is meant to.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_07_privesc

**What these assert.** Privilege escalation here is mass assignment: a
`ModelForm(fields="__all__")` binds `role` from the request. The exploit is a
`role=staff` POST that flips the flag gate open; the fix is an explicit `fields`
list that never binds `role`.
"""

from django.contrib.auth.models import User
from django.test import Client, TestCase

from .models import Flag, Profile
from .seed import FLAG


class PrivescLabTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user("alice", password="labpass")
        Profile.objects.create(user=self.alice, display_name="Alice", role="member")
        Flag.objects.create(value=FLAG)
        self.client = Client()
        self.client.force_login(self.alice)

    def role(self):
        return Profile.objects.get(user=self.alice).role

    def test_exploit_succeeds_on_vulnerable_view(self):
        # An injected `role=staff` is bound by fields="__all__" and written.
        self.client.post("/privesc/vulnerable/", {"role": "staff"})
        self.assertEqual(self.role(), "staff")
        # The escalation is real: the staff gate now hands over the flag.
        html = self.client.get("/privesc/staff-area/").content.decode()
        self.assertIn(FLAG, html)

    def test_exploit_is_blocked_on_secure_view(self):
        # The allowlist form has no `role` field, so the injection is dropped.
        self.client.post("/privesc/secure/", {"role": "staff"})
        self.assertEqual(self.role(), "member")
        resp = self.client.get("/privesc/staff-area/")
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn(FLAG, resp.content.decode())

    def test_secure_view_still_updates_safe_fields(self):
        # The fix does not break the legitimate edit: display_name still saves,
        # role still ignored.
        self.client.post(
            "/privesc/secure/",
            {"display_name": "Alice Updated", "role": "staff"},
        )
        fresh = Profile.objects.get(user=self.alice)
        self.assertEqual(fresh.display_name, "Alice Updated")
        self.assertEqual(fresh.role, "member")
