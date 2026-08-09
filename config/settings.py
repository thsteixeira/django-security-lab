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
    "labs",
    "labs.post_01_sql_injection",
    "labs.post_02_xss",
    "labs.post_03_ssti",
    "labs.post_06_idor",
    "labs.post_07_privesc",
    "labs.post_08_csrf",
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
]

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

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

STATIC_URL = "static/"

USE_TZ = True
