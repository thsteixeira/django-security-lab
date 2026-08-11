"""SECURE document download — the same feature, done safely.

Django ships `django.utils._os.safe_join`: it joins the base and the
user-supplied component, resolves the result to an absolute path, and verifies it
still starts with the base. If `../` sequences or an absolute path escape
DOCS_ROOT, it raises SuspiciousFileOperation instead of returning a path outside
the sandbox. We catch it and return a generic 404 — never the resolved path,
which would confirm the traversal attempt to the attacker.

    ?file=../flag.txt   -> safe_join raises SuspiciousFileOperation -> 404
    ?file=/abs/flag.txt -> safe_join raises SuspiciousFileOperation -> 404
    ?file=readme.txt    -> stays inside DOCS_ROOT -> the document is served

`safe_join` is the post's headline defence. (It normalizes lexically, not
symlink-aware; for a media root that can hold attacker-created symlinks the post
shows the Path.resolve()/is_relative_to() variant. This lab's root holds only
inert seeded files, so safe_join is the right primitive.)
"""
from django.core.exceptions import SuspiciousFileOperation
from django.http import Http404, HttpResponse
from django.utils._os import safe_join

from ._fs import DOCS_ROOT


def download(request):
    name = request.GET.get("file", "")
    if not name:
        return HttpResponse(
            "<h1>Secure document download</h1>"
            "<p>GET <code>?file=readme.txt</code> to download a document.</p>"
        )

    # SAFE: safe_join verifies the resolved path stays inside DOCS_ROOT. A
    # traversal payload raises SuspiciousFileOperation, which we turn into a 404.
    try:
        path = safe_join(str(DOCS_ROOT), name)
    except SuspiciousFileOperation:
        raise Http404()

    try:
        data = open(path, "rb").read()
    except OSError:
        raise Http404()
    return HttpResponse(data, content_type="text/plain")
