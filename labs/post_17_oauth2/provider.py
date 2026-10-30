"""The identity provider, played in-process.

A real provider (Google, Microsoft Entra ID, a company's Keycloak) is another
server. This lab runs offline — the web container has no route out (B6) — so the
provider lives here. Its OAuth half is correct, because that half is not the lesson:

- the authorize endpoint accepts only the registered client and an exactly matching
  redirect URI, and hands ``state`` back untouched;
- a code is single-use and only redeemable at the redirect URI it was issued for;
- the ID token is a signed JWT naming the issuer, the subject and the client.

What it shares with many real providers is a profile the account holder controls.
``/oauth2/provider/profile/`` lets an account set any email address and stores it as
unverified, and the ID token carries that address in its ``email`` claim, next to
``email_verified: false``. Every statement the provider signs is true: this account's
email *is* the address its holder typed. Whether that address identifies anyone on
the client's site is the client's decision.

Two stand-ins. ``?as=<username>`` replaces the provider's own sign-in page: whoever
sends it "signs in" at the provider as that account. And the token endpoint is a
function, ``redeem()``, rather than an HTTP endpoint, because the client and the
provider share one process and the class under study is the client's lookup, not
the transport.
"""

import secrets
import time

import jwt
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.utils.html import escape
from django.utils.http import urlencode
from django.views.decorators.http import require_GET

from .models import AuthorizationCode, ProviderAccount

ISSUER = "https://provider.lab.test"
CLIENT_ID = "django-security-lab"
# The provider signs ID tokens with HS256 and the client secret, one of the options
# OpenID Connect Core §10.1 allows. Not a secret worth protecting: this project is
# never deployed.
CLIENT_SECRET = "lab-client-secret-not-a-secret-never-deploy"

# Registered redirect URIs, compared by exact string. They are paths because the
# provider and the client share a host here.
REDIRECT_URIS = {
    "/oauth2/vulnerable/callback/",
    "/oauth2/secure/callback/",
    "/oauth2/connect/callback/",
}


class InvalidGrant(Exception):
    """The code is unknown, already used, or was issued for another redirect URI."""


def _account(request):
    return ProviderAccount.objects.filter(username=request.GET.get("as", "")).first()


@require_GET
def authorize(request):
    if request.GET.get("client_id") != CLIENT_ID:
        return HttpResponseBadRequest("unknown client_id\n")
    redirect_uri = request.GET.get("redirect_uri", "")
    if redirect_uri not in REDIRECT_URIS:
        return HttpResponseBadRequest("redirect_uri is not registered\n")
    account = _account(request)
    if account is None:
        return HttpResponseBadRequest(
            "sign in at the provider: add &as=alice or &as=bob to this URL\n"
        )

    code = AuthorizationCode.objects.create(
        code=secrets.token_urlsafe(24), subject=account.subject, redirect_uri=redirect_uri
    )
    params = {"code": code.code}
    if "state" in request.GET:
        params["state"] = request.GET["state"]
    return HttpResponseRedirect(f"{redirect_uri}?{urlencode(params)}")


@require_GET
def profile(request):
    """The account holder edits their profile. The new address is never checked."""
    account = _account(request)
    if account is None:
        return HttpResponseBadRequest("add as=alice or as=bob\n")
    email = request.GET.get("email", "")
    try:
        validate_email(email)
    except ValidationError:
        return HttpResponseBadRequest("add a well-formed email=...\n")
    account.email = email
    account.email_verified = False
    account.save()
    return HttpResponse(
        f"provider account {escape(account.username)}: email is now "
        f"{escape(account.email)} (unverified)\n"
    )


def redeem(code, redirect_uri, client_secret):
    """The token endpoint: trade a code for tokens, once."""
    if client_secret != CLIENT_SECRET:
        raise InvalidGrant("client authentication failed")
    claimed = AuthorizationCode.objects.filter(
        code=code, redirect_uri=redirect_uri, used=False
    ).update(used=True)
    if not claimed:
        raise InvalidGrant("unknown, used or mismatched code")

    subject = AuthorizationCode.objects.get(code=code).subject
    account = ProviderAccount.objects.get(subject=subject)
    now = int(time.time())
    id_token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": account.subject,
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            "email": account.email,
            "email_verified": account.email_verified,
        },
        CLIENT_SECRET,
        algorithm="HS256",
    )
    return {
        "access_token": secrets.token_urlsafe(24),
        "token_type": "Bearer",
        "id_token": id_token,
    }
