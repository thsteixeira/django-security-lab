"""VULNERABLE token handling — the claims are read, the signature never is.

This is the decode people reach for after an old tutorial stops working. Before
PyJWT 2.0, ``jwt.decode(token, verify=False)`` returned a token's claims without
checking anything. On PyJWT 2 the ``verify`` argument does nothing, so the call
fails asking for an ``algorithms`` list, and PyJWT's own deprecation warning
names the replacement: ``options={"verify_signature": False}``. Its documentation
shows the same call under "Reading the Claimset without Validation", beneath a
warning that it is "generally ill-advised".

The result runs, and it believes any payload anyone types. A token with
``"alg": "none"`` and no signature at all, or a real token whose payload was
edited after it was issued, decodes just the same. The view then looks up the
user the payload names and serves that user's export.

Every protection simplejwt and PyJWT have — the one-algorithm list, the key
checks, ``exp`` — lives inside the signature check, and this line switches the
check off. The secure twin does not hand-roll the decode at all.
"""

import jwt
from django.contrib.auth import get_user_model
from django.views.decorators.http import require_GET

from .exports import export_for

User = get_user_model()


@require_GET
def export_view(request):
    token = request.headers["Authorization"].removeprefix("Bearer ")
    # DANGER: verification is switched off, so these claims are whatever the
    # client wrote. An unsigned or edited token names any user it likes.
    claims = jwt.decode(token, options={"verify_signature": False})
    user = User.objects.get(pk=claims["user_id"])
    return export_for(user)
