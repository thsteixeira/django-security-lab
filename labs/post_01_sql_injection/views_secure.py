"""SECURE search view — the same feature, done safely.

The search term never touches the SQL string. The ORM sends a parameterised
query (`... WHERE title ILIKE %s`) and binds the value separately, so the same
UNION payload that captures the flag against the vulnerable view is treated as a
literal search string here and matches nothing.

No raw SQL string is built, so Bandit and the Semgrep community pack both stay
silent on this file — CI asserts exactly that.
"""
from django.http import HttpResponse
from django.utils.html import escape

from .models import Note

FLAG_PREFIX = "FLAG{"


def search(request):
    q = request.GET.get("q", "")

    # SAFE: the ORM parameterises the query — no SQL string is built from `q`.
    results = Note.objects.filter(title__icontains=q).values_list("id", "title", "body")

    captured = [r for r in results if FLAG_PREFIX in str(r[2])]
    banner = ""
    if captured:
        banner = "<p style='color:#c0392b'><strong>Flag captured?!</strong> (a bug)</p>"

    items = "".join(
        f"<li>{escape(str(title))} — {escape(str(body))}</li>" for _id, title, body in results
    )
    return HttpResponse(
        f"<h1>Secure search</h1><p>Query term: {escape(q)}</p>"
        f"{banner}<ul>{items or '<li>(no results)</li>'}</ul>"
    )
