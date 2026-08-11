"""Test fixture for rules/path_traversal.yaml — paired to the rule by filename
stem, so `semgrep --test --config rules/ rules/` checks the rule against it.

It mirrors Lab 09's two views and, crucially, the shape the official Semgrep
registry rule (python.django.security.injection.path-traversal.path-traversal-join)
MISSES: the two-hop multi-variable form (assign filename, build path, open path)
that the blog post teaches as Vulnerable Pattern 1. The inlined one-liner is here
too — the registry rule catches that one, and so must ours. The safe_join form is
the fix. The hardcoded-literal case documents the rule's one known limit (a
source-agnostic false positive, marked todook).
"""
import os

from django.core.exceptions import SuspiciousFileOperation
from django.http import Http404
from django.utils._os import safe_join

DOCS_ROOT = "/srv/documents"


def vulnerable_two_hop(request):
    # The realistic form the registry rule misses (request -> name -> path -> open).
    name = request.GET.get("file", "")
    path = os.path.join(DOCS_ROOT, name)
    # ruleid: thiagoteixeira.django.security.path-traversal.ospath-join-reaches-open
    return open(path, "rb").read()


def vulnerable_inlined(request):
    # The one-liner the registry rule catches — ours must too.
    # ruleid: thiagoteixeira.django.security.path-traversal.ospath-join-reaches-open
    return open(os.path.join(DOCS_ROOT, request.GET.get("file", "")), "rb").read()


def secure_safe_join(request):
    name = request.GET.get("file", "")
    try:
        path = safe_join(DOCS_ROOT, name)
    except SuspiciousFileOperation:
        raise Http404()
    # ok: thiagoteixeira.django.security.path-traversal.ospath-join-reaches-open
    return open(path, "rb").read()


def hardcoded_name_is_safe():
    # Every component is a literal, so this open() is safe — but the rule is
    # syntactic and source-agnostic, so it fires anyway. Known false positive.
    path = os.path.join(DOCS_ROOT, "readme.txt")
    # todook: thiagoteixeira.django.security.path-traversal.ospath-join-reaches-open
    return open(path, "rb").read()
