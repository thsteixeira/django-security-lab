"""Runnable proof that the vulnerable view leaks the flag and the secure one does not.

Run locally against SQLite:  LAB_DB=sqlite python manage.py test
Run in CI against Postgres:   python manage.py test
"""
from django.test import Client, TestCase

from .models import Flag, Note

FLAG = "FLAG{sql_injection_via_raw_string_interpolation}"
# Closes the LIKE literal, appends a UNION that reads the off-limits flag table,
# and comments out the trailing `%'`.
UNION_PAYLOAD = "' UNION SELECT id, 'x', value FROM sqli_flag -- "


class SqlInjectionLabTests(TestCase):
    def setUp(self):
        Note.objects.create(title="Welcome", body="a public note")
        Flag.objects.create(value=FLAG)
        self.client = Client()

    def test_vulnerable_view_leaks_flag_via_union(self):
        resp = self.client.get("/sql-injection/vulnerable/", {"q": UNION_PAYLOAD})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, FLAG)  # the injection captured the flag

    def test_secure_view_does_not_leak_flag(self):
        resp = self.client.get("/sql-injection/secure/", {"q": UNION_PAYLOAD})
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, "FLAG{")  # payload treated as a literal search term

    def test_secure_view_still_finds_real_matches(self):
        resp = self.client.get("/sql-injection/secure/", {"q": "Welcome"})
        self.assertContains(resp, "Welcome")
