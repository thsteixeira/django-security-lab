"""SECURE transfer — the same state change, with CSRF enforced.

`@csrf_protect` runs Django's real CSRF check on this view: a POST without a
valid `csrfmiddlewaretoken` (matching the `csrftoken` cookie set on GET) gets a
`403 Forbidden` before the view body runs. An attacker's cross-site form cannot
read the cookie's value from another origin, so it cannot produce a matching
token — the forgery is rejected while a legitimate, same-origin form still works.

In a default Django project the global `CsrfViewMiddleware` gives every view this
protection for free; this repo runs the middleware off (command-line-first), so
the secure view opts in explicitly. The security lesson is identical: a token the
attacker cannot forge.
"""
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect

from ._transfer import perform_transfer


@login_required
@csrf_protect
def transfer(request):
    return perform_transfer(request)
