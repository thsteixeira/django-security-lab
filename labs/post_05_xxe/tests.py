"""Runnable proof that the vulnerable webhook resolves an external entity (leaking
the flag off disk) while the defusedxml webhook rejects it, and still parses a
legitimate order.

Postgres is the only supported backend, and the lab is Linux-only — the flag is
read through a file:// URI. Run inside the Docker stack:

    docker compose run --rm web python manage.py test labs.post_05_xxe

The file-read payload declares an external entity pointing at the off-limits flag
file; the bomb payload nests internal entities (a small Billion Laughs). defusedxml
refuses the DTD/entities in both.
"""
from django.test import Client, TestCase

from ._fs import FLAG_PATH, ensure_layout
from .seed import FLAG

# XXE file read: the external entity resolves to the off-limits flag file.
XXE_FILE_READ = (
    '<?xml version="1.0"?>\n'
    f'<!DOCTYPE order [ <!ENTITY xxe SYSTEM "{FLAG_PATH.as_uri()}"> ]>\n'
    "<order><orderId>&xxe;</orderId></order>"
).encode()

# A small entity-expansion document (a miniature Billion Laughs) — enough to prove
# defusedxml refuses entity declarations without allocating a real bomb.
ENTITY_EXPANSION = (
    '<?xml version="1.0"?>\n'
    "<!DOCTYPE lolz [\n"
    '  <!ENTITY lol "lol">\n'
    '  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
    '  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">\n'
    "]>\n"
    "<lolz>&lol2;</lolz>"
).encode()

LEGIT = b"<order><orderId>A-100</orderId></order>"


class XXELabTests(TestCase):
    def setUp(self):
        ensure_layout(FLAG)          # the off-limits flag file the entity reads
        self.client = Client()

    def test_vulnerable_view_resolves_external_entity(self):
        resp = self.client.post(
            "/xxe/vulnerable/", data=XXE_FILE_READ, content_type="application/xml"
        )
        self.assertEqual(resp.status_code, 200)
        # The external entity was resolved and the flag came back in orderId.
        self.assertContains(resp, FLAG)

    def test_secure_view_rejects_external_entity(self):
        resp = self.client.post(
            "/xxe/secure/", data=XXE_FILE_READ, content_type="application/xml"
        )
        # defusedxml raised EntitiesForbidden; the flag was never read.
        self.assertEqual(resp.status_code, 400)
        self.assertNotContains(resp, "FLAG{", status_code=400)

    def test_secure_view_rejects_entity_expansion_bomb(self):
        resp = self.client.post(
            "/xxe/secure/", data=ENTITY_EXPANSION, content_type="application/xml"
        )
        # The bomb is refused at the DTD, never expanded.
        self.assertEqual(resp.status_code, 400)

    def test_secure_view_still_parses_a_legitimate_order(self):
        resp = self.client.post(
            "/xxe/secure/", data=LEGIT, content_type="application/xml"
        )
        self.assertEqual(resp.status_code, 200)
        # A document with no entities parses exactly as before.
        self.assertContains(resp, "A-100")
