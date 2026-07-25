"""Test fixture for rules/xss.yaml — paired to the rule by filename stem, so
`semgrep --test --config rules/ rules/` checks the rule against it.

It mirrors Lab 02's two views: mark_safe() on an unsanitised value is the bug;
mark_safe(nh3.clean(...)) is the fix. Lines annotated as a rule hit must match;
lines annotated ok must not. The two indirect cases document the rule's one
known limit — being syntactic, it cannot see sanitisation done through an
intermediate variable (a false positive marked todook).
"""
import nh3
from django.utils.html import escape, format_html
from django.utils.safestring import mark_safe


def vulnerable(comment):
    # ruleid: thiagoteixeira.django.security.xss.mark-safe-without-sanitiser
    return mark_safe(comment.body)


def secure_nh3(comment):
    # ok: thiagoteixeira.django.security.xss.mark-safe-without-sanitiser
    return mark_safe(nh3.clean(comment.body))


def secure_escaped(comment):
    # ok: thiagoteixeira.django.security.xss.mark-safe-without-sanitiser
    return mark_safe(escape(comment.body))


def safe_literal():
    # ok: thiagoteixeira.django.security.xss.mark-safe-without-sanitiser
    return mark_safe("<b>constant, not user input</b>")


def indirect_vulnerable(comment):
    body = comment.body
    # ruleid: thiagoteixeira.django.security.xss.mark-safe-without-sanitiser
    return mark_safe(body)


def indirect_sanitised(comment):
    # Sanitised one line up, through a variable. The rule SHOULD treat this as
    # safe but cannot (it is syntactic) - a known false positive, hence todook.
    clean = nh3.clean(comment.body)
    # todook: thiagoteixeira.django.security.xss.mark-safe-without-sanitiser
    return mark_safe(clean)
