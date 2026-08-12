from django.urls import path

from . import views_secure, views_vulnerable

urlpatterns = [
    path("vulnerable/", views_vulnerable.webhook, name="xxe_vulnerable"),
    path("secure/", views_secure.webhook, name="xxe_secure"),
]
