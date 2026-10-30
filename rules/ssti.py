"""Test fixture for rules/ssti.yaml — paired to the rule by filename stem, so
`semgrep --test --config rules/ rules/` checks the rule against it.

It mirrors Lab 03's two views: compiling a Template from user input is the bug;
passing user input as context data to a fixed-literal template is the fix. The
Jinja2 from_string() variant is the RCE case the post names. A
literal held in a variable is cleared by Semgrep's constant propagation (ok).
The two todook cases are the rule's false positives: a template file the
project ships, safe for a reason outside the code, and a sandboxed Jinja2
environment, which the rule cannot see.
"""
from pathlib import Path

from django.template import Context, Template, engines
from jinja2.sandbox import SandboxedEnvironment

_sandbox = SandboxedEnvironment(autoescape=True)


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
    # A fixed literal held in a variable: constant propagation sees the literal.
    tpl = "{{ value }}"
    # ok: thiagoteixeira.django.security.ssti.template-from-user-input
    return Template(tpl).render(Context({"value": "x"}))


def shipped_file():
    # A template file from the project's own repository. Safe, but the rule
    # cannot know who controls the file - a known false positive, hence todook.
    source = Path(__file__).with_name("greeting.txt").read_text()
    # todook: thiagoteixeira.django.security.ssti.template-from-user-input
    return Template(source).render(Context({"value": "x"}))


def sandboxed_jinja(request):
    # A sandboxed Jinja2 environment. The rule cannot tell _sandbox from a plain
    # Environment - a known false positive, hence todook.
    body = request.POST.get("body", "")
    # todook: thiagoteixeira.django.security.ssti.template-from-user-input
    return _sandbox.from_string(body).render({"user_name": "x"})
