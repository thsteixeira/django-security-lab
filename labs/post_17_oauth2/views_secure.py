"""SECURE "log in with the provider" — the callback finds the account by (iss, sub).

The same flow as the vulnerable twin, with one change: the local account is found
through an ``Identity`` row keyed on the ID token's ``iss`` and ``sub``, the pair
OpenID Connect guarantees to be unique and stable. The token's email plays no part.

An ``Identity`` row exists only if a user who was already signed in with their
password connected this provider account to their own (``views_connect.py``). A
provider account nobody connected opens no account here, whatever email it carries,
verified or not: the callback refuses it. A real project would send it to sign-up,
and, when its email already belongs to an account, to a page asking the user to
sign in the usual way and connect from there — which is what django-allauth does by
default.
"""

import secrets

from django.contrib.auth import login
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import redirect
from django.utils.crypto import constant_time_compare
from django.utils.html import escape

from . import idp
from .models import Identity

CALLBACK = "/oauth2/secure/callback/"


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
    identity = Identity.objects.filter(issuer=claims["iss"], subject=claims["sub"]).first()
    if identity is None:
        return HttpResponseForbidden("No account is linked to this provider account.\n")
    user = identity.user
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    return HttpResponse(f"logged in as {escape(user.username)}\n")
