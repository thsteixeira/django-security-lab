"""The OAuth client the views call: build the authorize URL, trade a code, check the ID token.

Everything in this module is correct, in both worlds. The vulnerable and secure
login callbacks differ only in the claim they use to find the local account.

``verify_id_token`` names the audience and the issuer and requires the claims the
callback relies on, so this lab is not also a token-substitution lab: an ID token
issued to another client, or by another issuer, is refused.
"""

import jwt
from django.utils.http import urlencode

from . import provider


def authorization_url(redirect_uri, state=None):
    params = {
        "client_id": provider.CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid",
    }
    if state is not None:
        params["state"] = state
    return f"/oauth2/provider/authorize/?{urlencode(params)}"


def exchange_code(code, redirect_uri):
    return provider.redeem(code, redirect_uri, client_secret=provider.CLIENT_SECRET)


def verify_id_token(id_token):
    return jwt.decode(
        id_token,
        provider.CLIENT_SECRET,
        algorithms=["HS256"],
        audience=provider.CLIENT_ID,
        issuer=provider.ISSUER,
        options={"require": ["iss", "sub", "aud", "exp", "iat"]},
    )
