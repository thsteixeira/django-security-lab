"""This lab's password policy — scoped to the lab, not bolted onto the project.

`AUTH_PASSWORD_VALIDATORS` is a **global** Django setting. Putting this policy
there would have applied it to every other lab in the repo, and the collision is
not hypothetical: the shared B7 cast password `labpass` is 7 characters and Lab
11's `summer2024` is 10, so both are rejected by a 15-character floor. Nothing
breaks while every lab writes passwords with `set_password()` (which never
validates), but the first lab built on Django's auth *forms* — `SetPasswordForm`,
`UserCreationForm`, `PasswordChangeForm`, all of which validate via
`SetPasswordMixin` — would have inherited this lab's policy by accident. Lab 14
(Password Reset) is form-based by design and would have been the first casualty.

So the policy lives here instead. `validate_password()` takes a third argument,
`password_validators`, for exactly this purpose: pass a list and it uses that
instead of reading the global setting. The config format is byte-identical to an
`AUTH_PASSWORD_VALIDATORS` block, so what you read here is what you would paste
into `settings.py` in a real project — which is what the blog post shows.

A happy side effect: `config/settings.py` keeps **no** `AUTH_PASSWORD_VALIDATORS`
at all, which means the project runs on Django's genuine default —
`AUTH_PASSWORD_VALIDATORS = []`, straight out of `django/conf/global_settings.py`.
That is the post's opening claim, now true of this repo rather than merely
described by it.
"""

import functools

from django.contrib.auth.password_validation import get_password_validators

# Shaped to NIST SP 800-63B-4 §3.1.1.2 rather than to habit: a 15-character floor
# for a single-factor password, NO composition rules (the standard says verifiers
# "SHALL NOT impose other composition rules"), and a blocklist, which is the one
# thing it SHALL do. Paste this straight into settings.py as
# AUTH_PASSWORD_VALIDATORS in a project that wants it applied everywhere.
PASSWORD_POLICY = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 15},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    {"NAME": "labs.post_13_weak_passwords.validators.BreachListValidator"},
]


@functools.cache
def get_policy():
    """Instantiate the policy once.

    Cached for the same reason Django caches `get_default_password_validators()`:
    `CommonPasswordValidator` and `BreachListValidator` each read and decompress a
    file into a set at construction, and doing that per request would be silly.
    """
    return get_password_validators(PASSWORD_POLICY)
