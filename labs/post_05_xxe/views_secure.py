"""SECURE XML webhook — the same feature, done safely.

The request body is parsed with defusedxml.ElementTree, the maintained drop-in
that forbids entity resolution and external references by default. When a hostile
document declares a custom entity or references an external resource, the parser
never reads a file, fetches a URL, or balloons in memory — it raises at once
(EntitiesForbidden / DTDForbidden / ExternalReferenceForbidden), which we turn
into a 400. A legitimate order document (no entities, no DTD) parses exactly as
before, so the feature still works.

defusedxml.ElementTree is the post's Rule 1 headline fix. (defusedxml also shipped
an lxml shim, but it is deprecated and slated for removal, so the maintained
ElementTree shim is the right choice.)
"""
import defusedxml.ElementTree as defused_etree
from defusedxml.common import (
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
)

from django.http import HttpResponse, JsonResponse


def webhook(request):
    if request.method != "POST":
        return HttpResponse(
            "<h1>Secure XML webhook</h1>"
            "<p>POST an <code>&lt;order&gt;&lt;orderId&gt;…&lt;/orderId&gt;&lt;/order&gt;</code> "
            "XML body.</p>"
        )

    # SAFE: defusedxml refuses DTDs and entities before parsing, so a file:// or
    # billion-laughs payload raises instead of executing. Legit XML is unaffected.
    try:
        root = defused_etree.fromstring(request.body)
    except (EntitiesForbidden, DTDForbidden, ExternalReferenceForbidden):
        return HttpResponse("Rejected: XML entities/DTDs are not allowed", status=400)

    order_id = root.findtext(".//orderId") or ""
    return JsonResponse({"received": order_id})
