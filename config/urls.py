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
        "<li>/command-injection/vulnerable/ and /command-injection/secure/ "
        "(POST name=sample.txt; cat ../flag.txt) &mdash; TIER 3, real RCE</li>"
        "<li>/xxe/vulnerable/ and /xxe/secure/ "
        "(POST an XML &lt;order&gt; body with a file:// external entity)</li>"
        "<li>/idor/vulnerable/&lt;pk&gt;/ and /idor/secure/&lt;pk&gt;/ "
        "&mdash; log in first: POST /accounts/login/</li>"
        "<li>/privesc/vulnerable/ and /privesc/secure/ (POST role=staff), "
        "then /privesc/staff-area/ &mdash; log in first</li>"
        "<li>/csrf/vulnerable/transfer/ and /csrf/secure/transfer/ "
        "(POST to_account=bob, no token), then /csrf/account/ &mdash; log in first</li>"
        '<li><a href="/path-traversal/vulnerable/?file=../flag.txt">/path-traversal/vulnerable/</a> '
        'and <a href="/path-traversal/secure/?file=../flag.txt">/path-traversal/secure/</a> '
        "(GET ?file=../flag.txt)</li>"
        "<li>/brute-force/vulnerable/login/ and /brute-force/secure/login/ "
        "(POST username=victim&amp;password=..., rotate X-Forwarded-For), then /brute-force/note/</li>"
        "<li>/mass-assignment/vulnerable/orders/&lt;pk&gt;/ and "
        "/mass-assignment/secure/orders/&lt;pk&gt;/ "
        "(PATCH price=0.00&amp;paid=true), then /mass-assignment/receipt/&lt;pk&gt;/</li>"
        "<li>/session/whoami/ (grab a sessionid), then POST bob's login to "
        "/session/vulnerable/login/ carrying it, then /session/secret/ &mdash; "
        "session fixation vs. /session/secure/login/ which rotates</li>"
        "<li>/passwords/vulnerable/register/ and /passwords/secure/register/ "
        "(POST username=mallory&amp;password=Password123!), then guess carol's "
        "password once at /accounts/login/ and read /passwords/secret/</li>"
        "<li>/password-reset/vulnerable/request/ and /password-reset/secure/request/ "
        "(POST email=dave@example.test), then replay the 400-day-old leaked token at "
        "/password-reset/vulnerable/confirm/&lt;uidb64&gt;/&lt;token&gt;/ &mdash; read the "
        "seed log for the link &mdash; and open /password-reset/vault/</li>"
        "<li>/mfa/vulnerable/dashboard/ and /mfa/secure/dashboard/ &mdash; log in as "
        "erin with her PASSWORD ONLY at /accounts/login/, then try both; the "
        "vulnerable one serves the flag, the secure one wants the second factor. "
        "POST a TOTP code to /mfa/{vulnerable,secure}/verify/</li>"
        "</ul>"
    )


urlpatterns = [
    path("", index),
    path("accounts/login/", auth_views.login_view, name="login"),
    path("accounts/logout/", auth_views.logout_view, name="logout"),
    path("sql-injection/", include("labs.post_01_sql_injection.urls")),
    path("xss/", include("labs.post_02_xss.urls")),
    path("ssti/", include("labs.post_03_ssti.urls")),
    path("command-injection/", include("labs.post_04_command_injection.urls")),
    path("xxe/", include("labs.post_05_xxe.urls")),
    path("idor/", include("labs.post_06_idor.urls")),
    path("privesc/", include("labs.post_07_privesc.urls")),
    path("csrf/", include("labs.post_08_csrf.urls")),
    path("path-traversal/", include("labs.post_09_path_traversal.urls")),
    path("mass-assignment/", include("labs.post_10_mass_assignment.urls")),
    path("brute-force/", include("labs.post_11_brute_force.urls")),
    path("session/", include("labs.post_12_session_fixation.urls")),
    path("passwords/", include("labs.post_13_weak_passwords.urls")),
    path("password-reset/", include("labs.post_14_password_reset.urls")),
    path("mfa/", include("labs.post_15_mfa.urls")),
]
