from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views_receipt, views_secure, views_vulnerable

vuln_router = DefaultRouter()
vuln_router.register(r"orders", views_vulnerable.OrderViewSet, basename="massassign-vuln-order")

secure_router = DefaultRouter()
secure_router.register(r"orders", views_secure.OrderViewSet, basename="massassign-secure-order")

urlpatterns = [
    path("vulnerable/", include(vuln_router.urls)),
    path("secure/", include(secure_router.urls)),
    path("receipt/<int:pk>/", views_receipt.receipt, name="massassign_receipt"),
]
