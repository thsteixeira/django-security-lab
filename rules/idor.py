"""Fixture for rules/idor.yaml — paired by filename stem for `semgrep --test`.

Mirrors the Lab 06 views: a get_object_or_404 scoped to the whole table (the
IDOR) vs. scoped to the requesting user (the fix). The `todook` / `todoruleid`
lines document the rule's honest limits, exactly as they read in rules/idor.yaml.
"""
from django.shortcuts import get_object_or_404, get_list_or_404

from .models import Document, Note, Profile


def vulnerable(request, pk):
    # ruleid: thiagoteixeira.django.security.idor.object-lookup-without-owner-scope
    return get_object_or_404(Note, pk=pk)


def vulnerable_list(request):
    # ruleid: thiagoteixeira.django.security.idor.object-lookup-without-owner-scope
    return get_list_or_404(Note)


def secure_owner(request, pk):
    # ok: thiagoteixeira.django.security.idor.object-lookup-without-owner-scope
    return get_object_or_404(Note, pk=pk, owner=request.user)


def secure_user(request, pk):
    # ok: thiagoteixeira.django.security.idor.object-lookup-without-owner-scope
    return get_object_or_404(Profile, pk=pk, user=request.user)


def false_positive_app_specific_scope(request, pk):
    # This lookup IS scoped to the requester, just through an app-specific field
    # name the syntactic rule doesn't know. It flags this anyway — a false
    # positive the analyst has to triage.
    # todook: thiagoteixeira.django.security.idor.object-lookup-without-owner-scope
    return get_object_or_404(Document, pk=pk, account=request.user)


def known_miss_raw_orm(request, pk):
    # The same bug via the raw ORM. This rule targets the get_object_or_404 /
    # get_list_or_404 shortcuts, so a bare .objects.get(pk=...) slips past it.
    # todoruleid: thiagoteixeira.django.security.idor.object-lookup-without-owner-scope
    return Note.objects.get(pk=pk)
