"""Runnable proof that the vulnerable view compiles user input as a template and
leaks the context secret, that the secure view keeps the same input as data and
never reaches the secret, and that the secure view still renders ordinary input.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test labs.post_03_ssti

**What these assert.** SSTI in DTL is context disclosure, not RCE — DTL never
evaluates expressions — so the exploit is `{{ flag }}` resolving to the secret,
and the fix is that the *same* payload comes back as the literal string.
"""

from django.test import Client, TestCase

from .models import Flag
from .seed import FLAG


class SstiLabTests(TestCase):
    def setUp(self):
        Flag.objects.create(value=FLAG)
        self.client = Client()

    def test_exploit_succeeds_on_vulnerable_view(self):
        # The attacker's `{{ flag }}` is compiled as the template and rendered
        # against the view's context, so it resolves to the secret.
        html = self.client.get("/ssti/vulnerable/", {"tpl": "{{ flag }}"}).content.decode()
        self.assertIn(FLAG, html)

    def test_exploit_is_blocked_on_secure_view(self):
        # The same payload is data: the fixed `{{ message }}` template emits it as
        # the literal string, and the secret is never reached — even though `flag`
        # is in the context exactly as in the vulnerable view.
        html = self.client.get("/ssti/secure/", {"tpl": "{{ flag }}"}).content.decode()
        self.assertIn("{{ flag }}", html)
        self.assertNotIn(FLAG, html)

    def test_secure_view_still_renders_a_legitimate_greeting(self):
        # Ordinary input (no template syntax) is echoed back — the feature still
        # works, it just treats the input as data.
        html = self.client.get("/ssti/secure/", {"tpl": "Happy Friday everyone"}).content.decode()
        self.assertIn("Happy Friday everyone", html)
