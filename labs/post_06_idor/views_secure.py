"""SECURE note detail view — the same feature, scoped to the owner.

The only change from the vulnerable twin is `owner=request.user` in the lookup.
`get_object_or_404` now queries `Note.objects.filter(pk=pk, owner=request.user)`:
a note that belongs to someone else is simply not in the result set, so Django
raises a 404 — the *same* response as a genuinely nonexistent id. The attacker
learns nothing about whether note 42 exists, and *bob*'s note stays private.

The invariant: never look up an object from the full table — filter by ownership
first, so authorisation is part of the query, not a forgotten afterthought.
"""
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils.html import escape

from .models import Note


@login_required
def note_detail(request, pk):
    # The lookup is scoped to the requester. Another user's note does not exist
    # in this queryset, so the response is an indistinguishable 404.
    note = get_object_or_404(Note, pk=pk, owner=request.user)
    return HttpResponse(
        "<h1>Secure note</h1>"
        f"<p>Viewing as <strong>{escape(request.user.username)}</strong></p>"
        f"<h2>{escape(note.title)}</h2>"
        f"<p>{escape(note.body)}</p>"
    )
