"""VULNERABLE note detail view — do NOT copy this into real code.

The view is *authenticated* (``@login_required``) but not *authorised*: the
lookup is `get_object_or_404(Note, pk=pk)`, scoped to the whole table rather than
to the requesting user. Any logged-in user can read any note by walking the
sequential primary keys — the textbook IDOR. Being logged in as *alice* is no
barrier to reading *bob*'s note, flag and all.

The fix (views_secure.py) adds one thing: `owner=request.user` to the lookup.
"""
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils.html import escape

from .models import Note


@login_required
def note_detail(request, pk):
    # DANGER: the lookup is never scoped to request.user. `pk` alone decides
    # what comes back, so any authenticated user reads any note.
    note = get_object_or_404(Note, pk=pk)
    return HttpResponse(
        "<h1>Vulnerable note</h1>"
        f"<p>Viewing as <strong>{escape(request.user.username)}</strong></p>"
        f"<h2>{escape(note.title)}</h2>"
        f"<p>{escape(note.body)}</p>"
    )
