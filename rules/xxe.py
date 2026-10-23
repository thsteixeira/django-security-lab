"""Test fixture for rules/xxe.yaml — paired to the rule by filename stem, so
`semgrep --test --config rules/ rules/` checks the rule against it.

It mirrors Lab 05's two views plus the shapes the post discusses: the explicit
resolve_entities=True footgun (Pattern 1), a bare lxml parse relying on implicit
defaults (Pattern 3), the defusedxml fix (Pattern 1's fix), and the hardened-lxml
fix (Pattern 3's fix). The last two must stay silent. The name-based false positive
(defusedxml imported *as* etree) is a todook case: the rule reports it.
"""
from lxml import etree

import defusedxml.ElementTree as defused_etree


def vulnerable_explicit(request):
    # ruleid: thiagoteixeira.django.security.xxe.lxml-parse-without-defusedxml
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(request.body, parser=parser)


def vulnerable_bare_defaults(request):
    # A bare lxml parse trusting lxml's version-dependent defaults (Pattern 3).
    # ruleid: thiagoteixeira.django.security.xxe.lxml-parse-without-defusedxml
    return etree.fromstring(request.body)


def vulnerable_bare_with_keyword(request):
    # Still no parser: another keyword does not harden the defaults.
    # ruleid: thiagoteixeira.django.security.xxe.lxml-parse-without-defusedxml
    return etree.fromstring(request.body, base_url="https://partner.example/")


def secure_defusedxml(request):
    # ok: thiagoteixeira.django.security.xxe.lxml-parse-without-defusedxml
    return defused_etree.fromstring(request.body)


def secure_hardened_lxml(raw):
    # Pattern 3's fix: a locked-down parser, correctly NOT flagged (the
    # footgun flag is off and the parse passes an explicit parser= object).
    # ok: thiagoteixeira.django.security.xxe.lxml-parse-without-defusedxml
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    return etree.fromstring(raw, parser=parser)


def false_positive_defusedxml_named_etree(raw):
    # Name-based: defusedxml imported under the name etree still matches.
    import defusedxml.ElementTree as etree
    # todook: thiagoteixeira.django.security.xxe.lxml-parse-without-defusedxml
    return etree.fromstring(raw)
