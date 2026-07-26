"""Test fixture for rules/ssti.yaml — paired to the rule by filename stem, so
`semgrep --test --config rules/ rules/` checks the rule against it.

It mirrors Lab 03's two views: compiling a Template from user input is the bug;
passing user input as context data to a fixed-literal template is the fix. The
Jinja2 from_string() variant is the Pattern 2 (RCE) case from the post. The
indirect case documents the rule's one known limit — being syntactic, it cannot
see that a variable holds a literal (a false positive marked todook).
"""
from django.template import Context, Template, engines


def vulnerable(request):
    tpl = request.GET.get("tpl", "")
    # ruleid: thiagoteixeira.django.security.ssti.template-from-user-input
    return Template(tpl).render(Context({}))


def vulnerable_jinja(request):
    body = request.POST.get("body", "")
    env = engines["jinja2"]
    # ruleid: thiagoteixeira.django.security.ssti.template-from-user-input
    return env.from_string(body).render({})


def secure_literal(request):
    tpl = request.GET.get("tpl", "")
    # ok: thiagoteixeira.django.security.ssti.template-from-user-input
    return Template("{{ value }}").render(Context({"value": tpl}))


def secure_jinja_literal(request):
    body = request.POST.get("body", "")
    env = engines["jinja2"]
    # ok: thiagoteixeira.django.security.ssti.template-from-user-input
    return env.from_string("{{ value }}").render({"value": body})


def indirect_literal():
    # A fixed literal held in a variable. The rule SHOULD treat this as safe but
    # cannot (it is syntactic) - a known false positive, hence todook.
    tpl = "{{ value }}"
    # todook: thiagoteixeira.django.security.ssti.template-from-user-input
    return Template(tpl).render(Context({"value": "x"}))
