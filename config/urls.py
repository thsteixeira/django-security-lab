from django.http import HttpResponse
from django.urls import include, path


def index(request):
    return HttpResponse(
        "<h1>django-security-lab</h1>"
        "<p>Intentionally vulnerable. Never deploy publicly.</p>"
        "<ul>"
        '<li><a href="/sql-injection/vulnerable/?q=test">/sql-injection/vulnerable/</a></li>'
        '<li><a href="/sql-injection/secure/?q=test">/sql-injection/secure/</a></li>'
        "</ul>"
    )


urlpatterns = [
    path("", index),
    path("sql-injection/", include("labs.post_01_sql_injection.urls")),
]
