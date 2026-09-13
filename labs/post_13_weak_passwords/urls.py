from django.urls import path

from . import views_account, views_form, views_secure, views_vulnerable

urlpatterns = [
    path("vulnerable/register/", views_vulnerable.register, name="wp_vulnerable"),
    path("secure/register/", views_secure.register, name="wp_secure"),
    path("form/register/", views_form.register, name="wp_form"),
    path("secret/", views_account.secret, name="wp_secret"),
]
