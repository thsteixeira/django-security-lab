"""VULNERABLE comment board — do NOT copy this into real code.

Comment bodies are user-supplied HTML. This view marks them safe with no
sanitisation, so autoescaping is switched off for that value and the attacker's
markup is emitted verbatim. Because the comment is stored, the payload is served
to every later visitor, inside the page's own origin, where an injected script
can read the session token out of the DOM.

`as_html` mirrors Django template autoescaping (see autoescape.py), so the
`mark_safe()` call is the operative mistake exactly as it would be in a
template. The secure twin (views_secure.py) differs by one call: nh3.clean().
"""
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
        # DANGER: untrusted HTML marked safe with no sanitisation whatsoever, so
        # as_html emits it verbatim. Bandit flags this mark_safe() call.
        f"<li><strong>{escape(c.author)}</strong>: {as_html(mark_safe(c.body))}</li>"
        for c in Comment.objects.order_by("id")
    )
    return HttpResponse(
        "<h1>Vulnerable comment board</h1>"
        "<p>Signed in as alice — session token: "
        f"<span id='session-token'>{escape(token)}</span></p>"
        f"<ul>{rows or '<li>(no comments yet)</li>'}</ul>"
    )
