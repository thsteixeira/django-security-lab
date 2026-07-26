"""VULNERABLE greeting renderer — do NOT copy this into real code.

The `tpl` query parameter is compiled *as a Django template* and rendered
against this view's context. The intended feature is a personalised greeting —
the user writes something like ``Hello {{ name }}`` — but because the user now
controls the template *source*, they can address any name in the context,
including ``flag``, a value the greeting feature was never meant to expose.

This is the DTL case, and it is deliberately *not* RCE: DTL does not evaluate
Python expressions, so ``{{7*7}}`` raises ``TemplateSyntaxError`` at parse time
and there is no path to the object graph. The damage is context disclosure —
exactly the boundary the blog post draws. The secure twin (views_secure.py)
differs by one thing: the user's input is passed as *data*, not compiled as the
template *source*.

The rendered output is escaped before it reaches the response, so a literal
``<script>`` in the template source cannot turn this into an XSS lab — the class
under study here is template injection and nothing else.
"""
from django.http import HttpResponse
from django.template import Context, Template
from django.utils.html import escape

from .models import Flag


def greeting(request):
    tpl = request.GET.get("tpl", "Hello!")
    flag = (Flag.objects.first() or Flag(value="")).value
    # DANGER: user input compiled AS a template. Every name the user writes is
    # resolved against this context — including `flag`, which the feature never
    # meant to hand out.
    rendered = Template(tpl).render(Context({"name": "world", "flag": flag}))
    return HttpResponse(
        "<h1>Vulnerable greeting</h1>"
        "<p>Renders your <code>?tpl=</code> as a template.</p>"
        f"<p>{escape(rendered)}</p>"
    )
