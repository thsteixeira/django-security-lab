"""VULNERABLE XML webhook — do NOT copy this into real code.

It parses the request body with an lxml parser built with resolve_entities=True,
so a document that declares an external entity makes the parser read that URI and
inline the result. The payload

    <!DOCTYPE order [ <!ENTITY xxe SYSTEM "file:///tmp/xxe/flag.txt"> ]>
    <order><orderId>&xxe;</orderId></order>

makes the parser read the off-limits flag file and hand it back in `orderId` —
XML External Entity injection (XXE). Point the entity at http://169.254.169.254/
instead and the same handler becomes an SSRF proxy to the cloud metadata endpoint
(here the no-egress `web` container blocks that; the file read still works).

The secure view (views_secure.py) routes the same request through defusedxml,
which refuses the DTD/entities and raises before any file is read.
"""
from lxml import etree

from django.http import HttpResponse, JsonResponse

# The footgun: resolve_entities=True expands &entity; references, including
# external SYSTEM entities that read local files (and, without no_network, fetch
# URLs). A parser left at unsafe settings is the whole vulnerability.
_UNSAFE_PARSER = etree.XMLParser(resolve_entities=True)


def webhook(request):
    if request.method != "POST":
        return HttpResponse(
            "<h1>Vulnerable XML webhook</h1>"
            "<p>POST an <code>&lt;order&gt;&lt;orderId&gt;…&lt;/orderId&gt;&lt;/order&gt;</code> "
            "XML body.</p>"
        )

    # DANGER: untrusted XML parsed with entity resolution on. An external-entity
    # payload reads whatever file the process can and returns it in orderId.
    root = etree.fromstring(request.body, parser=_UNSAFE_PARSER)
    order_id = root.findtext(".//orderId") or ""
    return JsonResponse({"received": order_id})
