# Fixture for rules/password_hashing.yaml — `semgrep --test` pairs them by filename stem.
#
# `ruleid` lines must be flagged, `ok` lines must not. `todoruleid` / `todook` mark
# the rule's own documented limits: shapes it should flag and does not, or flags and
# should not.

import hashlib
import hmac
import secrets

from django.conf import settings
from django.contrib.auth.hashers import get_hasher, make_password
from django.contrib.auth.models import User
from django.db import connection
from passlib.hash import md5_crypt

from .models import ApiKey, LegacyAccount


def lab_vulnerable_register(username, password):
    user = User(username=username)
    # ruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = hashlib.sha1(password.encode()).hexdigest()
    user.save()


def lab_secure_register(username, password):
    user = User(username=username)
    # ok: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.set_password(password)
    user.save()


def lab_vulnerable_backend(user, password):
    # ruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    return user.password == hashlib.sha1(password.encode()).hexdigest()


def lab_secure_check(user, password):
    # ok: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    return user.check_password(password)


def a_stronger_name_is_the_same_mistake(user, password):
    # SHA-256 is as fast as SHA-1 and just as unsalted here; the standard rules go
    # silent on it.
    # ruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = hashlib.sha256(password.encode()).hexdigest()


def silenced_for_bandit(user, password):
    # ruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest()


def through_a_local(user, password):
    digest = hashlib.blake2b(password.encode()).hexdigest()
    # ruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = digest


def by_name(user, password):
    # ruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = hashlib.new("sha512", password.encode()).hexdigest()


def peppered(user, password):
    # A secret key does not make HMAC slow: every guess is still one hash.
    # ruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = hmac.new(settings.SECRET_KEY.encode(), password.encode(), "sha256").hexdigest()


def salted_by_hand(user, password):
    # A salt makes it per row, but each guess is still one fast hash.
    salt = secrets.token_hex(8)
    # ruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = salt + "$" + hashlib.sha256((salt + password).encode()).hexdigest()


def created_with_it(username, password):
    # ruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    LegacyAccount.objects.create(username=username, password=hashlib.md5(password.encode()).hexdigest())


def bulk_reset(password):
    # ruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    User.objects.filter(is_active=False).update(password=hashlib.sha1(password.encode()).hexdigest())


def built_with_it(username, password):
    # ruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user = User(username=username, password=hashlib.sha256(password.encode()).hexdigest())
    user.save()


def a_string_encode_is_not_a_hasher(user, password):
    digest = hashlib.sha256(password.encode()).hexdigest()
    # ruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = digest.encode("ascii", "strict").decode()


def through_make_password(user, password):
    # ok: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = make_password(password)


def wrapped_by_hand(user):
    # Pattern 2's upgrade path: the old digest becomes a PBKDF2 input.
    hasher = get_hasher("pbkdf2_wrapped_sha1")
    # ok: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = hasher.encode_sha1_hash(user.password, hasher.salt())


def wrapped_inline(user, password):
    hasher = get_hasher("pbkdf2_sha256")
    # ok: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = hasher.encode(hashlib.sha1(password.encode()).hexdigest(), hasher.salt())


def wrapped_with_make_password(user, password):
    # ok: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = make_password(hashlib.sha1(password.encode()).hexdigest())


def create_user_hashes_what_it_is_given(username, password):
    # create_user() calls set_password(): the digest is stored inside PBKDF2.
    # ok: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    User.objects.create_user(username, password=hashlib.sha1(password.encode()).hexdigest())


def a_digest_that_is_not_stored(password):
    # A breached-password lookup by k-anonymity prefix never reaches a row.
    # ok: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    prefix = hashlib.sha1(password.encode()).hexdigest().upper()[:5]
    return prefix


def another_field_name(account, password):
    # todoruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    account.password_hash = hashlib.sha256(password.encode()).hexdigest()


def raw_sql(user_id, password):
    digest = hashlib.sha1(password.encode()).hexdigest()
    with connection.cursor() as cursor:
        # todoruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
        cursor.execute("UPDATE auth_user SET password = %s WHERE id = %s", [digest, user_id])


def a_third_party_fast_scheme(user, password):
    # todoruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = md5_crypt.hash(password)


def a_weak_kdf(user, password):
    # One iteration and a fixed salt: a fast hash in a KDF's clothes.
    # todoruleid: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    user.password = hashlib.pbkdf2_hmac("sha256", password.encode(), b"salt", 1).hex()


def an_api_key(owner):
    # A long random secret needs no slow hash: nobody can guess the input.
    token = secrets.token_urlsafe(32)
    # todook: thiagoteixeira.django.security.password_hashing.password-stored-as-a-fast-digest
    ApiKey.objects.create(owner=owner, password=hashlib.sha256(token.encode()).hexdigest())
    return token
