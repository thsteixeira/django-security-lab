"""Cross-lab shared helpers (B7).

Not a Django app — it ships no models and is not in INSTALLED_APPS. It holds the
standard user cast the authenticated labs share (``users.py``) and the shared
login/logout endpoints (``views.py``, wired at ``/accounts/`` in config/urls.py).
"""
