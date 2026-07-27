from django.http import HttpResponse
from django.urls import include, path

from labs._common import views as auth_views


def index(request):
    return HttpResponse(
        "<h1>django-security-lab</h1>"
        "<p>Intentionally vulnerable. Never deploy publicly.</p>"
        "<ul>"
        '<li><a href="/sql-injection/vulnerable/?q=test">/sql-injection/vulnerable/</a></li>'
        '<li><a href="/sql-injection/secure/?q=test">/sql-injection/secure/</a></li>'
        '<li><a href="/xss/vulnerable/">/xss/vulnerable/</a></li>'
        '<li><a href="/xss/secure/">/xss/secure/</a></li>'
        '<li><a href="/ssti/vulnerable/?tpl={{ flag }}">/ssti/vulnerable/</a></li>'
        '<li><a href="/ssti/secure/?tpl={{ flag }}">/ssti/secure/</a></li>'
        "<li>/idor/vulnerable/&lt;pk&gt;/ and /idor/secure/&lt;pk&gt;/ "
        "&mdash; log in first: POST /accounts/login/</li>"
        "</ul>"
    )


urlpatterns = [
    path("", index),
    path("accounts/login/", auth_views.login_view, name="login"),
    path("accounts/logout/", auth_views.logout_view, name="logout"),
    path("sql-injection/", include("labs.post_01_sql_injection.urls")),
    path("xss/", include("labs.post_02_xss.urls")),
    path("ssti/", include("labs.post_03_ssti.urls")),
    path("idor/", include("labs.post_06_idor.urls")),
]
