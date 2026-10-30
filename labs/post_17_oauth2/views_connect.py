"""Connect a provider account, and the account page — the same in both worlds, and correct.

"Connect" is how an ``Identity`` row comes to exist: a signed-in user enters their
password again and starts a sign-in at the provider, and the callback links the
provider account it comes back with — its (issuer, subject) — to that user. The flow
checks ``state``, so nobody can finish it in someone else's session.

The password is asked again because a session alone proves too little. In this lab the
vulnerable callback hands bob a session as alice; if that session were enough, bob
could connect his own provider account to her and walk in through the secure callback
too. Linking is the step that decides whose account a provider identity opens, so it
asks for proof of the account itself.

``/oauth2/account/`` shows the signed-in user's own notes. alice's holds the flag.
"""

import secrets

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import redirect
from django.utils.crypto import constant_time_compare
from django.utils.html import escape
from django.views.decorators.http import require_POST

from . import idp
from .models import Identity, Note

CALLBACK = "/oauth2/connect/callback/"


@login_required
@require_POST
def connect_start(request):
    if not request.user.check_password(request.POST.get("password", "")):
        return HttpResponseForbidden("Enter your password to connect a provider account.\n")
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
