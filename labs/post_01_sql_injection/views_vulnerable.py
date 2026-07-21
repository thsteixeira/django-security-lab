"""VULNERABLE search view — do NOT copy this into real code.

The search term is interpolated straight into a raw SQL string with an f-string,
so an attacker controls the query structure. A UNION payload pulls the CTF flag
out of the sqli_flag table, which this feature is never supposed to touch.

CI scans this file with Bandit and the Semgrep community Django pack and asserts
both fire here (and stay silent on views_secure.py). See
labs/post_01_sql_injection/README.md for the exploit walkthrough and the
captured SAST + DAST output.
"""
from django.db import connection
from django.http import HttpResponse
from django.utils.html import escape

FLAG_PREFIX = "FLAG{"


def search(request):
    q = request.GET.get("q", "")

    with connection.cursor() as cursor:
        # DANGER: user input interpolated into the SQL string. Bandit B608 and
        # the Semgrep community rule both flag this line.
        cursor.execute(
            f"SELECT id, title, body FROM sqli_note WHERE title LIKE '%{q}%'"
        )
        rows = cursor.fetchall()

    captured = [r for r in rows if FLAG_PREFIX in str(r[2])]
    banner = ""
    if captured:
        flag = escape(captured[0][2])
        banner = f"<p style='color:#c0392b'><strong>Flag captured:</strong> {flag}</p>"

    items = "".join(
        f"<li>{escape(str(title))} — {escape(str(body))}</li>" for _id, title, body in rows
    )
    return HttpResponse(
        f"<h1>Vulnerable search</h1><p>Query term: {escape(q)}</p>"
        f"{banner}<ul>{items or '<li>(no results)</li>'}</ul>"
    )
