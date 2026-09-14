from django.urls import path

from . import views_secure, views_verify, views_vulnerable

urlpatterns = [
    path("vulnerable/dashboard/", views_vulnerable.dashboard, name="mfa_vulnerable"),
    path("secure/dashboard/", views_secure.dashboard, name="mfa_secure"),
    # Correct in both worlds — see views_verify.py.
    path("verify/", views_verify.verify, name="mfa_verify"),
]
