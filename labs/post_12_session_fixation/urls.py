from django.urls import path

from . import views_secure, views_session, views_vulnerable

urlpatterns = [
    path("vulnerable/login/", views_vulnerable.login_view, name="sf_vulnerable"),
    path("secure/login/", views_secure.login_view, name="sf_secure"),
    path("whoami/", views_session.whoami, name="sf_whoami"),
    path("secret/", views_session.secret, name="sf_secret"),
]
