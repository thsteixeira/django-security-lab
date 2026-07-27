from django.urls import path

from . import views_secure, views_vulnerable

urlpatterns = [
    path("vulnerable/<int:pk>/", views_vulnerable.note_detail, name="idor_vulnerable"),
    path("secure/<int:pk>/", views_secure.note_detail, name="idor_secure"),
]
