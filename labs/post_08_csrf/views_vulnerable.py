"""VULNERABLE transfer — do NOT copy this into real code.

`@csrf_exempt` is the pattern Post 8 names as the entire CSRF surface: it tells
Django's `CsrfViewMiddleware` to skip the token check on this view. An attacker
hosts a hidden form that POSTs here; the victim's browser attaches their session
cookie automatically; nothing asks "did you *mean* to send this?", so the
transfer executes. `@login_required` is still here — it confirms the session is
valid, which is exactly the trust CSRF abuses.

NOTE on this repo: to keep the other command-line labs token-free, this project
runs **without a global `CsrfViewMiddleware`** (see settings.py). So `@csrf_exempt`
here is illustrative of the real-world pattern rather than the operative removal
— the view is unprotected either way, which is the point. The secure twin opts
into protection with `@csrf_protect`; in a default Django project you would get
that protection for free from the middleware and *this* view's `@csrf_exempt`
would be the whole bug.
"""
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

from ._transfer import perform_transfer


@csrf_exempt
@login_required
def transfer(request):
    return perform_transfer(request)
