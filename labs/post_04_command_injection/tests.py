"""Runnable proof that the vulnerable inspector executes injected shell commands
(leaking the flag) while the secure one does not, and still inspects real files.

Postgres is the only supported backend, and the lab is Linux-only — one /bin/sh,
one meaning for `;`. Both hold inside the Docker stack:

    docker compose run --rm web python manage.py test labs.post_04_command_injection

These tests really do run `wc -c sample.txt; cat ../flag.txt` in the container —
that is the point. B6 (non-root, no network egress) is what makes running real
command execution here acceptable.
"""
from django.test import Client, TestCase

from ._fs import SAMPLE_BODY, SAMPLE_NAME, ensure_layout
from .seed import FLAG

# A shell metacharacter turns the single `wc` call into two commands.
PAYLOAD = f"{SAMPLE_NAME}; cat ../flag.txt"


class CommandInjectionLabTests(TestCase):
    def setUp(self):
        ensure_layout(FLAG)          # uploads/sample.txt + the off-limits flag file
        self.client = Client()

    def test_vulnerable_view_executes_injected_command(self):
        resp = self.client.post("/command-injection/vulnerable/", {"name": PAYLOAD})
        self.assertEqual(resp.status_code, 200)
        # The `;` started a second command that read the off-limits flag.
        self.assertContains(resp, FLAG)

    def test_secure_view_does_not_execute_injection(self):
        resp = self.client.post("/command-injection/secure/", {"name": PAYLOAD})
        self.assertEqual(resp.status_code, 200)
        # The payload was passed to wc as one literal (missing) filename.
        self.assertNotContains(resp, "FLAG{")

    def test_secure_view_still_inspects_a_real_file(self):
        resp = self.client.post("/command-injection/secure/", {"name": SAMPLE_NAME})
        self.assertEqual(resp.status_code, 200)
        # wc -c reports the byte count of the real sample file.
        self.assertContains(resp, str(len(SAMPLE_BODY.encode())))
