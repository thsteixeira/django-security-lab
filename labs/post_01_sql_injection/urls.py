from django.urls import path

from . import views_secure, views_vulnerable

urlpatterns = [
    path("vulnerable/", views_vulnerable.search, name="sqli_vulnerable"),
    path("secure/", views_secure.search, name="sqli_secure"),
]
