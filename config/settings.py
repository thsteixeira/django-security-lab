"""
Django settings for the django-security-lab project.

This project is INTENTIONALLY VULNERABLE. Never deploy it to a public host.
See SECURITY.md. It is meant to run only on a local machine or in CI, bound
to 127.0.0.1 via docker-compose.

Database: PostgreSQL, read from environment variables and served by the
docker-compose stack. A single backend keeps what you run identical to what CI
runs and to the scanner output committed under each lab's scans/ directory.
"""
import os
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Not a secret worth protecting — this app is never deployed. Constant for reproducibility.
SECRET_KEY = "django-security-lab-not-a-secret-never-deploy-this"

# DEBUG is on so learners see the tracebacks and SQL. Never do this in production.
DEBUG = True

ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",       # B1 — the auth/session stack the Wave 2 labs need
    "django.contrib.sessions",   # B1 — session-cookie auth (Series II/III labs)
    "django.contrib.staticfiles",
    "rest_framework",            # B4 — DRF stack, introduced with Lab 10 (mass assignment)
    # B8 — the MFA stack, introduced with Lab 15. django_otp adds the device
    # models; otp_totp is the TOTP plugin. Both are inert for every other lab:
    # no device rows exist, so nothing changes for them.
    "django_otp",
    "django_otp.plugins.otp_totp",
    # B12 — the JWT stack, introduced with Lab 16. The blacklist app stores
    # issued and revoked refresh tokens; the SIMPLE_JWT block below needs it for
    # BLACKLIST_AFTER_ROTATION. Inert for every lab that issues no JWT.
    "rest_framework_simplejwt.token_blacklist",
    "labs",
    "labs.post_01_sql_injection",
    "labs.post_02_xss",
    "labs.post_03_ssti",
    "labs.post_04_command_injection",
    "labs.post_05_xxe",
    "labs.post_06_idor",
    "labs.post_07_privesc",
    "labs.post_08_csrf",
    "labs.post_09_path_traversal",
    "labs.post_10_mass_assignment",
    "labs.post_11_brute_force",
    "labs.post_12_session_fixation",
    "labs.post_13_weak_passwords",
    "labs.post_14_password_reset",
    "labs.post_15_mfa",
    "labs.post_16_jwt",
    "labs.post_17_oauth2",
]

# B1 — the auth/session stack. CSRF is DELIBERATELY NOT global: CsrfViewMiddleware
# would force a token on every POST in every lab (including the shipped 01–03 and
# every manual `curl`), which fights the command-line-first convention. The CSRF
# lab (post 08) turns protection on *for its own secure view only*, so it can show
# exempt-vs-protected side by side. AuthenticationMiddleware must follow
# SessionMiddleware.
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # B8 — OTPMiddleware must follow AuthenticationMiddleware. It sets
    # request.user.otp_device (None unless a verified device is on the session)
    # and is what makes request.user.is_verified() answerable at all. Inert for
    # the other labs: with no device on the session it just records None.
    "django_otp.middleware.OTPMiddleware",
]

# NOTE: there is deliberately NO AUTH_PASSWORD_VALIDATORS here, so this project
# runs on Django's genuine default — `AUTH_PASSWORD_VALIDATORS = []` in
# django/conf/global_settings.py. The four-validator block everyone recognises
# comes from the `startproject` TEMPLATE, not from the framework.
#
# Lab 13 needs a real policy, but it keeps it in labs/post_13_weak_passwords/
# policy.py and passes it to validate_password(password_validators=...) rather
# than setting it here — a global setting would have silently applied this lab's
# 15-character floor to every other lab. See CONTRIBUTING.md, "Settings are
# global; lab behaviour should not be."

# Lab 14 sends a password-reset email, and the link inside it *is* the thing under
# study — so mail has to go somewhere a reader can read. The console backend prints
# it to the `docker compose up` log; nothing leaves the container. Django's test
# runner overrides this with the locmem backend automatically, which is how
# tests.py reads the same link out of `django.core.mail.outbox`.
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# B12 — the JWT configuration, introduced with Lab 16. A global setting on
# purpose: this block IS the lesson (see CONTRIBUTING.md, "Settings are global;
# lab behaviour should not be"), and no other lab issues a JWT. simplejwt's
# defaults sign with SECRET_KEY, keep access tokens five minutes and refresh
# tokens a day, never rotate, and never revoke on a password change; this is the
# fix. The signing key comes from the environment, or is drawn at random when the
# process starts — never SECRET_KEY, which is committed above. A random key means
# tokens do not survive a restart, which is fine for a lab and the honest default:
# a key in the repository is a key everyone has. Any later JWT lab inherits this
# block; change it knowingly.
JWT_SIGNING_KEY = os.environ.get("JWT_SIGNING_KEY") or secrets.token_urlsafe(48)

SIMPLE_JWT = {
    "SIGNING_KEY": JWT_SIGNING_KEY,
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "CHECK_REVOKE_TOKEN": True,
}

# @login_required redirects here (POST-only endpoint; a GET just 405s, which is a
# fine "you must log in" signal for a lab).
LOGIN_URL = "/accounts/login/"

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
            ]
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "lab"),
        "USER": os.environ.get("POSTGRES_USER", "lab"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "lab"),
        "HOST": os.environ.get("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
    }
}

# Pinned so the throttle counters in Lab 11 behave identically under the test
# runner and `runserver` (gate 3). LocMemCache is per-process — fine for the
# single-process dev server and the tests (which clear() it) — but a multi-worker
# production deployment would need a shared store (see labs/post_11_brute_force).
CACHES = {
    "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

STATIC_URL = "static/"

USE_TZ = True
