"""Runnable proof that the vulnerable download escapes the document root (leaking
the flag) while the secure `safe_join` view returns 404, and still serves a real
document.

Postgres is the only supported backend, and the lab is Linux-only — POSIX `/`
separators, one meaning for `../`. Run inside the Docker stack:

    docker compose run --rm web python manage.py test labs.post_09_path_traversal

The two payloads mirror the post's two variants: a relative `../` that climbs out
of documents/, and an absolute path that `os.path.join` substitutes for the base
entirely. `safe_join` blocks both.
"""
from django.test import Client, TestCase

from ._fs import FLAG_PATH, README_BODY, README_NAME, ensure_layout
from .seed import FLAG

# Relative traversal: one `../` climbs from documents/ to its parent, then reads
# the off-limits flag.
RELATIVE_PAYLOAD = "../flag.txt"
# Absolute-path injection: os.path.join(base, "/abs/path") discards base and
# returns the absolute path. FLAG_PATH is already absolute.
ABSOLUTE_PAYLOAD = str(FLAG_PATH)


class PathTraversalLabTests(TestCase):
    def setUp(self):
        ensure_layout(FLAG)          # documents/readme.txt + the off-limits flag file
        self.client = Client()

    def test_vulnerable_view_leaks_flag_via_relative_traversal(self):
        resp = self.client.get("/path-traversal/vulnerable/", {"file": RELATIVE_PAYLOAD})
        self.assertEqual(resp.status_code, 200)
        # The `../` escaped documents/ and read the flag one level above it.
        self.assertContains(resp, FLAG)

    def test_vulnerable_view_leaks_flag_via_absolute_path(self):
        resp = self.client.get("/path-traversal/vulnerable/", {"file": ABSOLUTE_PAYLOAD})
        self.assertEqual(resp.status_code, 200)
        # os.path.join dropped DOCS_ROOT and opened the absolute path.
        self.assertContains(resp, FLAG)

    def test_secure_view_blocks_relative_traversal(self):
        resp = self.client.get("/path-traversal/secure/", {"file": RELATIVE_PAYLOAD})
        # safe_join raised SuspiciousFileOperation, turned into a generic 404.
        self.assertEqual(resp.status_code, 404)
        self.assertNotContains(resp, "FLAG{", status_code=404)

    def test_secure_view_blocks_absolute_path(self):
        resp = self.client.get("/path-traversal/secure/", {"file": ABSOLUTE_PAYLOAD})
        self.assertEqual(resp.status_code, 404)
        self.assertNotContains(resp, "FLAG{", status_code=404)

    def test_secure_view_still_serves_a_legitimate_document(self):
        resp = self.client.get("/path-traversal/secure/", {"file": README_NAME})
        self.assertEqual(resp.status_code, 200)
        # The safe path stays inside documents/, so the real file is served.
        self.assertContains(resp, README_BODY.strip())
