from django.urls import path

from . import views_secure, views_vulnerable

urlpatterns = [
    path("vulnerable/", views_vulnerable.greeting, name="ssti_vulnerable"),
    path("secure/", views_secure.greeting, name="ssti_secure"),
]
