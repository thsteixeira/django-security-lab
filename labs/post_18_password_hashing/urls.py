from django.urls import path

from . import views_note, views_secure, views_vulnerable

urlpatterns = [
    path("vulnerable/register/", views_vulnerable.register, name="ph_vulnerable_register"),
    path("vulnerable/login/", views_vulnerable.login, name="ph_vulnerable_login"),
    path("secure/register/", views_secure.register, name="ph_secure_register"),
    # The secure login is the shared /accounts/login/ (Django's ModelBackend).
    path("note/", views_note.note, name="ph_note"),
]
