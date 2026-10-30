"""Test fixture for rules/path_traversal.yaml — paired to the rule by filename
stem, so `semgrep --test --config rules/ rules/` checks the rule against it.

It mirrors Lab 09's two views and, crucially, the shape the official Semgrep
registry rule (python.django.security.injection.path-traversal.path-traversal-join)
MISSES: the two-hop form with a .get() default (read the filename, build the
path, open the path) that the blog post teaches as Pattern 1. The inlined
one-liner is here too — the registry rule catches that one, and so must ours —
plus a longer chain, the pathlib forms (open(), .read_bytes(), .open()), a URL
kwarg (function and class-based view), a containment check that only logs and
one on an unresolved path. The safe_join form, a record lookup
and a symlink-aware check are the fixes; a hardcoded join and a non-view
helper must stay silent too. The regex-validated case documents the rule's one
false positive (todook).
"""
import os
import re
from pathlib import Path

from django.core.exceptions import SuspiciousFileOperation
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.utils._os import safe_join

DOCS_ROOT = "/srv/documents"


def vulnerable_two_hop(request):
    # The realistic form the registry rule misses (request -> name -> path -> open).
    name = request.GET.get("file", "")
    path = os.path.join(DOCS_ROOT, name)
    # ruleid: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return open(path, "rb").read()


def vulnerable_inlined(request):
    # The one-liner the registry rule catches — ours must too.
    # ruleid: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return open(os.path.join(DOCS_ROOT, request.GET.get("file", "")), "rb").read()


def vulnerable_three_hop(request):
    # A longer chain: the registry rule has no shape for it.
    raw = request.GET.get("file", "")
    name = raw.strip()
    path = os.path.join(DOCS_ROOT, name)
    # ruleid: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return open(path, "rb").read()


def vulnerable_pathlib(request):
    # pathlib's / operator has the same two failure modes as os.path.join.
    path = Path(DOCS_ROOT) / request.GET["file"]
    # ruleid: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return open(path, "rb").read()


def vulnerable_url_kwarg(request, filename):
    # The filename arrives as a URL parameter (path("<path:filename>", ...); the
    # <str:...> converter admits no "/", so it could not carry "../x").
    path = os.path.join(DOCS_ROOT, filename)
    # ruleid: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return open(path, "rb").read()


def vulnerable_pathlib_read_bytes(request):
    # The post lists Path.read_bytes() among the reads Django does not guard.
    # ruleid: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return (Path(DOCS_ROOT) / request.GET["file"]).read_bytes()


def vulnerable_pathlib_open(request):
    path = Path(DOCS_ROOT) / request.GET.get("file", "")
    # ruleid: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    with path.open("rb") as fh:
        return fh.read()


def vulnerable_check_on_unresolved_path(request):
    # is_relative_to() is lexical: /srv/documents/../flag.txt "is relative to"
    # /srv/documents. Without resolve() the check passes the payload.
    base = Path(DOCS_ROOT)
    candidate = base / request.GET.get("file", "")
    if not candidate.is_relative_to(base):
        raise Http404()
    # ruleid: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return open(candidate, "rb").read()


class DocumentView:
    def get(self, request, filename):
        # A class-based view's URL kwarg follows `self, request`.
        path = os.path.join(DOCS_ROOT, filename)
        # ruleid: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
        return open(path, "rb").read()


def vulnerable_check_only_logs(request):
    # A containment check that does not stop the request contains nothing.
    base = Path(DOCS_ROOT).resolve()
    candidate = (base / request.GET.get("file", "")).resolve()
    if not candidate.is_relative_to(base):
        print("escape attempt")
    # ruleid: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return candidate.read_bytes()


def secure_safe_join(request):
    name = request.GET.get("file", "")
    try:
        path = safe_join(DOCS_ROOT, name)
    except SuspiciousFileOperation:
        raise Http404()
    # ok: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return open(path, "rb").read()


def secure_record_lookup(request, document_id):
    # The post's Pattern 2 fix: the URL carries an ID, the FileField holds the path.
    doc = get_object_or_404(Document, pk=document_id, owner=request.user)
    # ok: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return doc.file.open("rb").read()


def secure_symlink_aware(request):
    # A symlink-aware check: resolve() follows links, then contain.
    base = Path(DOCS_ROOT).resolve()
    candidate = (base / request.GET.get("file", "")).resolve()
    if not candidate.is_relative_to(base):
        raise Http404()
    # ok: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return open(candidate, "rb").read()


def hardcoded_name_is_safe():
    # Every component is a literal and nothing comes from a request.
    path = os.path.join(DOCS_ROOT, "readme.txt")
    # ok: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return open(path, "rb").read()


def helper_not_a_view(base, filename):
    # No `request` parameter, so its arguments are not treated as sources.
    path = os.path.join(base, filename)
    # ok: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return open(path, "rb").read()


def validated_by_regex(request):
    # Safe: the allowlist regex admits no separator and no dot-dot. Semgrep cannot
    # read the check, so the rule fires anyway. Known false positive.
    name = request.GET.get("file", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]+\.txt", name):
        raise Http404()
    path = os.path.join(DOCS_ROOT, name)
    # todook: thiagoteixeira.django.security.path-traversal.request-data-reaches-open
    return open(path, "rb").read()
