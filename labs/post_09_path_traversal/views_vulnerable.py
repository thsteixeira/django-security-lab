"""VULNERABLE document download — do NOT copy this into real code.

It builds a filesystem path with `os.path.join(DOCS_ROOT, name)` from the
user-supplied `?file=` parameter and opens the result. `os.path.join` is a string
concatenator: it never normalizes or checks the path, so a `../` payload climbs
out of DOCS_ROOT and an absolute path discards the base entirely.

    ?file=../flag.txt   -> reads the off-limits flag one level above documents/
    ?file=/abs/flag.txt -> os.path.join drops DOCS_ROOT and opens the abs path

This is the shape of the post's Vulnerable Pattern 1/2 (MEDIA_ROOT + a filename
from the URL). The secure view (views_secure.py) swaps the join for Django's
`safe_join`, which raises SuspiciousFileOperation on exactly these payloads.

Served as text/plain so a traversed HTML file can't turn this into an XSS demo —
this teaches path traversal and nothing else.
"""
import os

from django.http import Http404, HttpResponse

from ._fs import DOCS_ROOT


def download(request):
    name = request.GET.get("file", "")
    if not name:
        return HttpResponse(
            "<h1>Vulnerable document download</h1>"
            "<p>GET <code>?file=readme.txt</code> to download a document.</p>"
        )

    # DANGER: os.path.join does not check containment. `../` escapes DOCS_ROOT and
    # an absolute component replaces it, so the user chooses which file is read.
    path = os.path.join(str(DOCS_ROOT), name)
    try:
        data = open(path, "rb").read()
    except OSError:
        raise Http404()
    return HttpResponse(data, content_type="text/plain")
