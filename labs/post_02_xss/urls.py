from django.urls import path

from . import views_secure, views_vulnerable

urlpatterns = [
    path("vulnerable/", views_vulnerable.board, name="xss_vulnerable"),
    path("secure/", views_secure.board, name="xss_secure"),
]
