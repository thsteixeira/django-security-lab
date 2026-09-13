"""The privilege boundary: dave's stored items, served only to dave's session.

Scoped to ``request.user`` with no id in the URL, so the lab cannot drift into
IDOR (that is Post 6), and escaped on the way out, so it is not an XSS lab either
(Post 2). The only way to read this is to hold a session that belongs to dave —
which, in this lab, means having completed a password reset you had no right to
complete.
"""

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.utils.html import escape

from .models import VaultItem


@login_required
def vault(request):
    rows = VaultItem.objects.filter(owner=request.user)
    if not rows:
        return HttpResponse(
            f"<h1>Vault</h1><p>{escape(request.user.username)} has no items.</p>"
        )
    body = "".join(
        f"<p>{escape(request.user.username)}: {escape(row.body)}</p>" for row in rows
    )
    return HttpResponse(f"<h1>Vault</h1>{body}")
