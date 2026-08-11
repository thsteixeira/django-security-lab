from django.urls import path

from . import views_secure, views_vulnerable

urlpatterns = [
    path("vulnerable/", views_vulnerable.download, name="traversal_vulnerable"),
    path("secure/", views_secure.download, name="traversal_secure"),
]
