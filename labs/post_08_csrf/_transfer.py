"""Shared transfer logic for both twins. The ONLY difference between the
vulnerable and secure views is the CSRF decorator each applies — the state
change itself is identical, so it lives here.
"""
from django.http import HttpResponse
from django.middleware.csrf import get_token
from django.utils.html import escape

from .models import Account


def perform_transfer(request):
    if request.method == "POST":
        to_username = request.POST.get("to_account", "")
        sender = Account.objects.get(user=request.user)
        recipient = Account.objects.filter(user__username=to_username).first()
        moved = ""
        # The recipient must exist and differ from the sender — scoped so this
        # does not drift into an IDOR/object-reference lab.
        if recipient and sender.holdings and recipient.pk != sender.pk:
            moved = sender.holdings
            recipient.holdings, sender.holdings = sender.holdings, ""
            recipient.save()
            sender.save()
        return HttpResponse(
            "<h1>Transfer</h1>"
            f"<p>moved <strong>{escape(moved) or '(nothing)'}</strong> "
            f"from {escape(request.user.username)} to {escape(to_username)}</p>"
        )

    # GET renders the form. Calling get_token() sets the csrftoken cookie, so the
    # secure view (and a legitimate browser) can obtain a valid token.
    token = get_token(request)
    return HttpResponse(
        "<h1>Transfer</h1>"
        '<form method="post">'
        f'<input type="hidden" name="csrfmiddlewaretoken" value="{token}">'
        '<input name="to_account" placeholder="recipient username">'
        '<button type="submit">Transfer my holdings</button>'
        "</form>"
    )
