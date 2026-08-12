"""Test fixture for rules/xxe.yaml — paired to the rule by filename stem, so
`semgrep --test --config rules/ rules/` checks the rule against it.

It mirrors Lab 05's two views plus the shapes the post discusses: the explicit
resolve_entities=True footgun (Pattern 1), a bare lxml parse relying on implicit
defaults (Pattern 3), the defusedxml fix (Rule 1), and the hardened-lxml fix
(Rule 2). The last two must stay silent. The name-based false positive
(defusedxml imported *as* etree) documents the rule's one honest limit.
"""
from lxml import etree

import defusedxml.ElementTree as defused_etree


def vulnerable_explicit(request):
    # ruleid: thiagoteixeira.django.security.xxe.lxml-parse-without-defusedxml
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(request.body, parser=parser)


def vulnerable_bare_defaults(request):
    # A bare lxml parse trusting libxml2's version-dependent defaults (Pattern 3).
    # ruleid: thiagoteixeira.django.security.xxe.lxml-parse-without-defusedxml
    return etree.fromstring(request.body)


def secure_defusedxml(request):
    # ok: thiagoteixeira.django.security.xxe.lxml-parse-without-defusedxml
    return defused_etree.fromstring(request.body)


def secure_hardened_lxml(raw):
    # The "Rule 2" fallback: a locked-down parser, correctly NOT flagged (the
    # footgun flag is off and the parse passes an explicit parser= object).
    # ok: thiagoteixeira.django.security.xxe.lxml-parse-without-defusedxml
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    return etree.fromstring(raw, parser=parser)
