from django.urls import path

from . import provider, views_connect, views_secure, views_vulnerable

urlpatterns = [
    # The in-lab identity provider (see provider.py).
    path("provider/authorize/", provider.authorize, name="oauth2_provider_authorize"),
    path("provider/profile/", provider.profile, name="oauth2_provider_profile"),
    # "Log in with the provider": the pair under study.
    path("vulnerable/login/", views_vulnerable.login_start, name="oauth2_vulnerable_login"),
    path("vulnerable/callback/", views_vulnerable.login_callback, name="oauth2_vulnerable_callback"),
    path("secure/login/", views_secure.login_start, name="oauth2_secure_login"),
    path("secure/callback/", views_secure.login_callback, name="oauth2_secure_callback"),
    # Connect a provider account, and the account page — the same in both worlds.
    path("connect/", views_connect.connect_start, name="oauth2_connect"),
    path("connect/callback/", views_connect.connect_callback, name="oauth2_connect_callback"),
    path("account/", views_connect.account, name="oauth2_account"),
]
