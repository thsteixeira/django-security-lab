from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from . import views_logout, views_secure, views_vulnerable

urlpatterns = [
    # simplejwt's own views, configured by the project's SIMPLE_JWT block.
    path("token/", TokenObtainPairView.as_view(), name="jwt_token"),
    path("token/refresh/", TokenRefreshView.as_view(), name="jwt_refresh"),
    path("vulnerable/export/", views_vulnerable.export_view, name="jwt_vulnerable"),
    path("secure/export/", views_secure.export_view, name="jwt_secure"),
    # Insecure in both worlds — see views_logout.py.
    path("logout/", views_logout.LogoutView.as_view(), name="jwt_logout"),
]
