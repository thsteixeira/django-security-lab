# Fixture for rules/oauth2.yaml — `semgrep --test` pairs them by filename stem.
#
# `ruleid` lines must be flagged, `ok` lines must not. `todoruleid` / `todook` mark
# the rule's own documented limits: shapes it should flag and does not, or flags and
# should not.

import jwt
import requests
from django.contrib.auth.models import User
from django.db.models import Q

from . import idp
from .models import Identity


def lab_vulnerable_callback(request):
    tokens = idp.exchange_code(request.GET["code"], redirect_uri="/cb/")
    claims = idp.verify_id_token(tokens["id_token"])
    # ruleid: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    user = User.objects.filter(email__iexact=claims["email"]).first()
    return user


def lab_secure_callback(request):
    tokens = idp.exchange_code(request.GET["code"], redirect_uri="/cb/")
    claims = idp.verify_id_token(tokens["id_token"])
    # ok: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    identity = Identity.objects.filter(issuer=claims["iss"], subject=claims["sub"]).first()
    return identity


def decoded_by_hand(id_token, key):
    claims = jwt.decode(id_token, key, algorithms=["RS256"], audience="client")
    # ruleid: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    return User.objects.get(email=claims["email"])


def through_a_local(id_token, key):
    claims = jwt.decode(id_token, key, algorithms=["RS256"], audience="client")
    address = claims.get("email")
    # ruleid: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    user, _ = User.objects.get_or_create(email=address)
    return user


def even_when_marked_verified(id_token, key):
    claims = jwt.decode(id_token, key, algorithms=["RS256"], audience="client")
    if claims.get("email_verified"):
        # Flagged on purpose: email_verified is a claim about someone else's
        # verification, and the identifier is still a reassignable address.
        # ruleid: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
        return User.objects.filter(email__iexact=claims["email"]).first()
    return None


def creating_a_new_account_is_not_a_lookup(id_token, key):
    claims = jwt.decode(id_token, key, algorithms=["RS256"], audience="client")
    # ok: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    return User.objects.create_user(username=claims["sub"], email=claims["email"])


def password_reset_form(request):
    # An email typed into a form is not a provider's claim; the rule must not touch it.
    # ok: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    return User.objects.filter(email__iexact=request.POST["email"]).first()


def keyed_on_a_username_claim(id_token, key):
    claims = jwt.decode(id_token, key, algorithms=["RS256"], audience="client")
    # Same class (preferred_username is reassignable), outside the rule's email scope.
    # todoruleid: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    return User.objects.get(username=claims["preferred_username"])


def from_the_userinfo_endpoint(access_token):
    # Plain-OAuth providers answer "who is this" from an API call, not an ID token.
    # The response is not a source the rule knows.
    profile = requests.get("https://provider.example/userinfo",
                           headers={"Authorization": f"Bearer {access_token}"}, timeout=5).json()
    # todoruleid: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    return User.objects.get(email=profile["email"])


def inside_a_q_object(id_token, key):
    claims = jwt.decode(id_token, key, algorithms=["RS256"], audience="client")
    # Same lookup, but the email is an argument of Q(), not a keyword of filter().
    # todoruleid: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    return User.objects.filter(Q(email__iexact=claims["email"])).first()


def inside_an_in_list(id_token, key):
    claims = jwt.decode(id_token, key, algorithms=["RS256"], audience="client")
    # `email__in` is outside the keyword regex.
    # todoruleid: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    return User.objects.filter(email__in=[claims["email"]]).first()


def through_a_queryset_variable(id_token, key):
    claims = jwt.decode(id_token, key, algorithms=["RS256"], audience="client")
    users = User.objects.all()
    # The receiver is a variable, not `$MODEL.objects`.
    # todoruleid: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    return users.filter(email__iexact=claims["email"]).first()


def signup_asks_whether_the_address_is_taken(id_token, key):
    claims = jwt.decode(id_token, key, algorithms=["RS256"], audience="client")
    # Only asks whether the address is in use, to send the user to "sign in and
    # connect"; nobody is logged in by it. The rule cannot tell.
    # todook: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    return User.objects.filter(email__iexact=claims["email"]).exists()


def pinned_to_the_signed_in_user(request, id_token, key):
    claims = jwt.decode(id_token, key, algorithms=["RS256"], audience="client")
    # The pk fixes whose row this is; the email cannot choose another user.
    # todook: thiagoteixeira.django.security.oauth2.account-found-by-email-claim
    return User.objects.filter(pk=request.user.pk, email__iexact=claims["email"]).exists()
