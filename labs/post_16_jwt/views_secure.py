"""SECURE token handling — let DRF authenticate the request, and read request.user.

No hand-rolled decode. ``JWTAuthentication`` decodes with the project's
``SIGNING_KEY`` and a one-element ``algorithms`` list taken from settings, so the
token never chooses how it is checked. It then checks the token type (an access
token, not a refresh token), ``exp``, that the user it names still exists and is
active, and — with ``CHECK_REVOKE_TOKEN`` on, as this project sets it — that the
user's password has not changed since the token was issued.

A forged, edited or expired token never reaches the view body: DRF answers 401
before ``get()`` runs. The view itself has nothing left to decide.

The settings this relies on are the project's ``SIMPLE_JWT`` block in
``config/settings.py``: its own signing key (not ``SECRET_KEY``), five-minute
access tokens, refresh rotation with the blacklist, and ``CHECK_REVOKE_TOKEN``.
"""

from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from .exports import export_for


class ExportView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return export_for(request.user)


export_view = ExportView.as_view()
