from django.urls import path

from . import views_secure, views_vault, views_vulnerable

urlpatterns = [
    path(
        "vulnerable/request/",
        views_vulnerable.request_reset,
        name="pr_vulnerable_request",
    ),
    path(
        "vulnerable/confirm/<uidb64>/<token>/",
        views_vulnerable.confirm,
        name="pr_vulnerable_confirm",
    ),
    path("secure/request/", views_secure.request_reset, name="pr_secure_request"),
    path(
        "secure/confirm/<uidb64>/<token>/",
        views_secure.confirm,
        name="pr_secure_confirm",
    ),
    path("vault/", views_vault.vault, name="pr_vault"),
]
