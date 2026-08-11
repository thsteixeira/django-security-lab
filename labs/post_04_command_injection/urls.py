from django.urls import path

from . import views_secure, views_vulnerable

urlpatterns = [
    path("vulnerable/", views_vulnerable.inspect, name="cmdinj_vulnerable"),
    path("secure/", views_secure.inspect, name="cmdinj_secure"),
]
