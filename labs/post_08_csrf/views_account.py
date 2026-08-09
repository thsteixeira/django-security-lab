"""Shared read-only view: shows the logged-in user's holdings.

Used to *see* the theft — after a forged transfer moves the flag from the victim
to the attacker, the attacker logs in here and finds it in their account.
"""
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.utils.html import escape

from .models import Account


@login_required
def account(request):
    acct = Account.objects.get(user=request.user)
    return HttpResponse(
        "<h1>Account</h1>"
        f"<p>{escape(request.user.username)} holdings: "
        f"<strong>{escape(acct.holdings) or '(empty)'}</strong></p>"
    )
