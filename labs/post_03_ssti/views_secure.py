"""SECURE greeting renderer — the same feature, user input kept as data.

The template *source* is a fixed literal the developer controls (``{{ message }}``);
the user's ``tpl`` value is passed into the context as data. DTL substitutes it
as a string and never re-parses it, so ``{{ flag }}`` comes back as the literal
text ``{{ flag }}`` — not the secret — even though ``flag`` is in the context,
exactly as it is in the vulnerable view. The only thing that changed is who
controls the template source.

The invariant: user input is context *data*, never template *source*.
"""
from django.http import HttpResponse
from django.template import Context, Template
from django.utils.html import escape

from .models import Flag


def greeting(request):
    tpl = request.GET.get("tpl", "Hello!")
    flag = (Flag.objects.first() or Flag(value="")).value
    # The user's input is DATA, substituted into a fixed template the developer
    # controls. Same context as the vulnerable view — the fix is structural, not
    # a matter of keeping secrets out of the context.
    rendered = Template("{{ message }}").render(
        Context({"message": tpl, "name": "world", "flag": flag})
    )
    return HttpResponse(
        "<h1>Secure greeting</h1>"
        "<p>Renders your <code>?tpl=</code> as data.</p>"
        f"<p>{escape(rendered)}</p>"
    )
