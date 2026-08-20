"""Two supporting endpoints:

- ``whoami`` establishes/inspects a session. An anonymous GET here creates a
  session and returns its id — the value an attacker "fixes" onto a victim.
- ``secret`` is the prize: bob's private data, readable only from bob's own
  authenticated session. Riding the fixated (never-rotated) session reaches it.
"""
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.utils.html import escape

from .models import Secret


def whoami(request):
    # Touch the session so an anonymous visitor is issued a sessionid cookie —
    # this is the id an attacker captures and fixes onto the victim. Save now so
    # the key is assigned and can be printed (otherwise it is None until response).
    request.session["visited"] = True
    if request.session.session_key is None:
        request.session.save()
    who = request.user.username if request.user.is_authenticated else "anonymous"
    return HttpResponse(
        f"session={request.session.session_key} user={escape(who)}\n"
    )


@login_required
def secret(request):
    s = Secret.objects.filter(owner=request.user).first()
    body = s.body if s else "(no secret for this account)"
    return HttpResponse(
        f"<h1>Private secret</h1><p>{escape(request.user.username)}: "
        f"{escape(body)}</p>"
    )
