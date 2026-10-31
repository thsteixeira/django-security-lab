"""The signed-in user's private notes — the same page in both worlds.

The lookup is scoped to ``request.user`` (no IDOR, Lab 6) and the output is
escaped (no XSS, Lab 2). carla's note holds the flag, so reaching it means holding
a session as carla, which means knowing her password.
"""

from django.http import HttpResponse
from django.utils.html import escape

from .models import Note


def note(request):
    if not request.user.is_authenticated:
        return HttpResponse("log in first\n", status=401)
    bodies = Note.objects.filter(owner=request.user).values_list("body", flat=True)
    items = "".join(f"<li>{escape(body)}</li>" for body in bodies)
    return HttpResponse(
        f"<h1>{escape(request.user.username)}'s notes</h1><ul>{items}</ul>\n"
    )
