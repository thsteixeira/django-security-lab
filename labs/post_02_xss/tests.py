"""Runnable proof that the vulnerable board ships live attacker markup to the
browser, that the secure board neutralises it, and that the fix does not break
legitimate rich text.

Postgres is the only supported backend, locally and in CI:

    docker compose run --rm web python manage.py test

**What these assert, and what they cannot.** The test client does not run
JavaScript, so they check the *markup that reaches the browser* — a live
`onerror` attribute versus escaped/stripped output. Whether the handler then
fires is a browser concern; the README shows how to see that with one curl.
"""

from django.test import Client, TestCase

from .models import Comment, Flag
from .seed import FLAG

# The stored-XSS shape: an image whose broken-load handler reads the session
# token out of the DOM. In a browser this exfiltrates it; here it is the proof
# that live, executable markup reached the page.
PAYLOAD = (
    "<img src=x onerror=\"alert(document.getElementById('session-token').textContent)\">"
)

LEGITIMATE = "Nice post <strong>thanks</strong>"


class XssLabTests(TestCase):
    def setUp(self):
        Flag.objects.create(value=FLAG)
        Comment.objects.create(author="mallory", body=PAYLOAD)
        Comment.objects.create(author="alice", body=LEGITIMATE)
        self.client = Client()

    def test_exploit_succeeds_on_vulnerable_view(self):
        html = self.client.get("/xss/vulnerable/").content.decode()
        # The stored comment reached the browser as LIVE markup — a real <img>
        # tag with its handler intact, not escaped entities.
        self.assertIn("<img src=x onerror=", html)
        # And the token the payload targets is sitting in the DOM to be read.
        self.assertIn(FLAG, html)

    def test_exploit_is_blocked_on_secure_view(self):
        html = self.client.get("/xss/secure/").content.decode()
        # nh3 strips the event handler, so nothing executes.
        self.assertNotIn("onerror=", html)

    def test_secure_view_still_renders_legitimate_markup(self):
        html = self.client.get("/xss/secure/").content.decode()
        # The fix sanitises rich text rather than escaping or dropping it.
        self.assertIn("<strong>thanks</strong>", html)
