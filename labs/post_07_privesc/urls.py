from django.urls import path

from . import views_secure, views_staffarea, views_vulnerable

urlpatterns = [
    path("vulnerable/", views_vulnerable.edit_profile, name="privesc_vulnerable"),
    path("secure/", views_secure.edit_profile, name="privesc_secure"),
    path("staff-area/", views_staffarea.staff_area, name="privesc_staff_area"),
]
