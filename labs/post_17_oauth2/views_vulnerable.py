"""VULNERABLE "log in with the provider" — the callback finds the account by email.

The flow is otherwise correct: the start view sends a ``state`` and the callback
checks it, the code is exchanged once, and the ID token's signature, issuer,
audience and expiry are verified. The mistake is the claim the callback chooses to
find the local account. It reads ``email``, and email is a profile field at the
provider, not an identity: the provider signs whatever address the account holder
typed in (this one stores it as unverified and says so in ``email_verified``).

So the attacker sets their own provider account's email to the victim's address and
signs in. The provider authenticates the attacker, with the attacker's password, and
signs a true statement about the attacker's account; the callback reads the address,
finds the victim's row, and logs the attacker into it. OpenID Connect Core §5.7:
``email`` "MUST NOT be used as unique identifiers"; ``iss`` plus ``sub`` is "the only
guaranteed unique identifier".
"""

import secrets

from django.contrib.auth import get_user_model, login
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect
from django.utils.crypto import constant_time_compare
from django.utils.html import escape

from . import idp

User = get_user_model()

CALLBACK = "/oauth2/vulnerable/callback/"


def login_start(request):
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    return redirect(idp.authorization_url(redirect_uri=CALLBACK, state=state))


def login_callback(request):
    expected = request.session.pop("oauth_state", None)
    if not expected or not constant_time_compare(expected, request.GET.get("state", "")):
        return HttpResponseBadRequest("Invalid state")
    tokens = idp.exchange_code(request.GET["code"], redirect_uri=CALLBACK)
    claims = idp.verify_id_token(tokens["id_token"])
    # DANGER: email is a profile claim the account holder controls, not an identity.
    user = User.objects.filter(email__iexact=claims["email"]).first()
    if user is None:
        user = User.objects.create_user(username=claims["sub"], email=claims["email"])
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    return HttpResponse(f"logged in as {escape(user.username)}\n")
