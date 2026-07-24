"""A stand-in for Django template autoescaping.

These labs are exercised from the command line (curl), not through a browser or
a template, but XSS via ``mark_safe`` is fundamentally a *template-escaping*
mistake. Django templates HTML-escape every ``{{ value }}`` unless the value is
a ``SafeString`` — which is exactly what ``mark_safe()`` and the ``|safe``
filter produce.

``as_html`` reproduces that one rule, so ``mark_safe()`` is the operative
decision in the views: mark a value safe and it is emitted verbatim; drop the
``mark_safe`` and the same value is escaped and harmless. That is the behaviour
a real template would give you, made visible in a plain view.
"""
from django.utils.html import escape
from django.utils.safestring import SafeString


def as_html(value):
    """Escape ``value`` for HTML output, unless it has been marked safe."""
    return value if isinstance(value, SafeString) else escape(value)
