"""Connect a provider account, and the account page — the same in both worlds, and correct.

"Connect" is how an ``Identity`` row comes to exist: a user who is already signed in
with their password starts a sign-in at the provider, and the callback links the
provider account it comes back with — its (issuer, subject) — to that user. The flow
checks ``state``, so nobody can finish it in someone else's session.

``/oauth2/account/`` shows the signed-in user's own notes. alice's holds the flag.
"""

import secrets

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect
from django.utils.crypto import constant_time_compare
from django.utils.html import escape

from . import idp
from .models import Identity, Note

CALLBACK = "/oauth2/connect/callback/"


@login_required
def connect_start(request):
    state = secrets.token_urlsafe(32)
    request.session["oauth_connect_state"] = state
    return redirect(idp.authorization_url(redirect_uri=CALLBACK, state=state))


@login_required
def connect_callback(request):
    expected = request.session.pop("oauth_connect_state", None)
    if not expected or not constant_time_compare(expected, request.GET.get("state", "")):
        return HttpResponseBadRequest("Invalid state")
    tokens = idp.exchange_code(request.GET["code"], redirect_uri=CALLBACK)
    claims = idp.verify_id_token(tokens["id_token"])
    Identity.objects.create(user=request.user, issuer=claims["iss"], subject=claims["sub"])
    return HttpResponse(
        f"connected provider subject {escape(claims['sub'])} to {escape(request.user.username)}\n"
    )


@login_required
def account(request):
    notes = Note.objects.filter(owner=request.user)
    body = "".join(f"<p>{escape(note.body)}</p>" for note in notes)
    return HttpResponse(f"<h1>{escape(request.user.username)}'s account</h1>{body}")
