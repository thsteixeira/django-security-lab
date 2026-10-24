"""Logout — the same in both worlds, and insecure in both.

This file is neither the vulnerable view nor the secure one. It is the logout
endpoint most simplejwt projects write, and no setting fixes it, so there is no
secure twin to diff against.

It blacklists the refresh token, so that token can no longer mint new access
tokens. It does nothing to the access token that authenticated this very request:
``AccessToken`` does not inherit simplejwt's ``BlacklistMixin``, only
``RefreshToken`` and ``SlidingToken`` do. A copy of the access token keeps working
until its ``exp``. With this project's five-minute lifetime that window is small;
it is not zero, and making it zero means checking every access token's ``jti``
against a denylist on every request.

``tests.py`` records that as an ``expectedFailure``: a test that says what this
project accepts, and fails the day someone builds the denylist.
"""

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken


# INSECURE — logs out the refresh token, not the user
class LogoutView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        RefreshToken(request.data["refresh"]).blacklist()
        return Response(status=205)
