"""The export both views serve, so the two views differ only in who they believe.

Output is escaped: this is a lab about trusting a token, not about rendering one
(XSS is Lab 02).
"""

from django.http import HttpResponse
from django.utils.html import escape

from .models import ExportRecord


def export_for(user):
    rows = ExportRecord.objects.filter(owner=user)
    if not rows:
        return HttpResponse(
            f"<h1>Export</h1><p>{escape(user.username)} has no records.</p>"
        )
    body = "".join(f"<p>{escape(user.username)}: {escape(row.body)}</p>" for row in rows)
    return HttpResponse(f"<h1>Export</h1>{body}")
