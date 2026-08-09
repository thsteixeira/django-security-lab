from django.urls import path

from . import views_account, views_secure, views_vulnerable

urlpatterns = [
    path("vulnerable/transfer/", views_vulnerable.transfer, name="csrf_vulnerable"),
    path("secure/transfer/", views_secure.transfer, name="csrf_secure"),
    path("account/", views_account.account, name="csrf_account"),
]
