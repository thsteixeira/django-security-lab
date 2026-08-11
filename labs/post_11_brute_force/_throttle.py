"""Shared throttle primitives for both login twins.

A deliberately tiny hand-rolled counter in the cache — the point of the lab is
what it is *keyed on*, not the machinery. `django-axes` is the production answer
(it counts per account in the DB and works across processes); see the README.

CACHE NOTE (gate 3): the default cache is `LocMemCache`, which is per-process.
That is fine here — `runserver` handles requests in one process, and the tests
call `cache.clear()` around each case — but a multi-worker production deployment
would need a shared store (another reason real projects reach for django-axes).
"""
from django.core.cache import cache

FAILURE_LIMIT = 5
WINDOW_SECONDS = 300


def register_failure(key):
    """Count one failed attempt against `key`; returns the new total."""
    total = cache.get(key, 0) + 1
    cache.set(key, total, WINDOW_SECONDS)
    return total


def is_locked(key):
    return cache.get(key, 0) >= FAILURE_LIMIT


def client_ip_from_forwarded_for(request):
    """VULNERABLE client-IP resolution: trusts the *first* X-Forwarded-For hop,
    which is whatever the client typed. Rotating that header hands the attacker a
    fresh rate-limit bucket on every request — from a single machine."""
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()  # DANGER: attacker-controlled
    return request.META.get("REMOTE_ADDR", "")
