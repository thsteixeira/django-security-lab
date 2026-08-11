from django.urls import path

from . import views_note, views_secure, views_vulnerable

urlpatterns = [
    path("vulnerable/login/", views_vulnerable.login_view, name="bf_vulnerable"),
    path("secure/login/", views_secure.login_view, name="bf_secure"),
    path("note/", views_note.note, name="bf_note"),
]
