"""SECURE comment board — the same feature, one call different.

nh3.clean() runs the untrusted HTML through an allowlist before mark_safe():
disallowed tags, event-handler attributes (onerror, onload, …) and unsafe URL
schemes (javascript:, data:) are stripped. What survives is safe to mark safe,
and legitimate rich text (a <strong>, an <em>) still renders — the feature is
fixed, not removed.
"""
import nh3
from django.http import HttpResponse
from django.utils.html import escape
from django.utils.safestring import mark_safe

from .autoescape import as_html
from .models import Comment, Flag


def board(request):
    if request.method == "POST":
        Comment.objects.create(
            author=request.POST.get("author", "anonymous")[:80],
            body=request.POST.get("body", ""),
        )

    token = (Flag.objects.first() or Flag(value="")).value
    rows = "".join(
        # Sanitised against an allowlist first, and only then marked safe.
        f"<li><strong>{escape(c.author)}</strong>: {as_html(mark_safe(nh3.clean(c.body)))}</li>"
        for c in Comment.objects.order_by("id")
    )
    return HttpResponse(
        "<h1>Secure comment board</h1>"
        "<p>Signed in as alice — session token: "
        f"<span id='session-token'>{escape(token)}</span></p>"
        f"<ul>{rows or '<li>(no comments yet)</li>'}</ul>"
    )
