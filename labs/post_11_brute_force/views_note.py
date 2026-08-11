"""The prize: the victim's private note, readable only from the victim's own
authenticated session. Cracking the password on the vulnerable login logs the
attacker in as the victim; this view then hands over the flag."""
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.utils.html import escape

from .models import Note


@login_required
def note(request):
    n = Note.objects.filter(owner=request.user).first()
    body = n.body if n else "(no note)"
    return HttpResponse(
        f"<h1>Private note</h1><p>{escape(request.user.username)}: "
        f"{escape(body)}</p>"
    )
