"""The privilege boundary: carol's private data, served only to carol's session.

Guessing a weak password is worth nothing until it buys something. This endpoint
is what it buys — the flag lives in the victim's own ``Secret`` row, so capturing
it requires an authenticated session belonging to the victim, which requires
knowing the password the vulnerable registration view agreed to store.

Scoped to ``request.user`` (no id in the URL) so the lab does not drift into
IDOR — that is Post 6. Output is escaped: this is not an XSS lab either.
"""

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.utils.html import escape

from .models import Secret


@login_required
def secret(request):
    rows = Secret.objects.filter(owner=request.user)
    if not rows:
        return HttpResponse(
            f"<h1>Private secret</h1><p>{escape(request.user.username)} has none.</p>"
        )
    body = "".join(
        f"<p>{escape(request.user.username)}: {escape(row.body)}</p>" for row in rows
    )
    return HttpResponse(f"<h1>Private secret</h1>{body}")
