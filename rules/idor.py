"""Fixture for rules/idor.yaml — paired by filename stem for `semgrep --test`.

Mirrors the Lab 06 views: a get_object_or_404 scoped to the whole table (the
IDOR) vs. scoped to the requesting user (the fix). The `todook` / `todoruleid`
lines document the rule's honest limits, exactly as they read in rules/idor.yaml.
`semgrep --test` does not enforce todo annotations, so a JSON scan of this file
is what shows the rule matching under every `todook` line and no `todoruleid` line.
"""
from django.shortcuts import get_object_or_404, get_list_or_404
from rest_framework import viewsets

from .models import Document, Note, Post, Profile


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


def false_positive_related_manager(request, pk):
    # Scoped through the requester's own related manager, so only their notes
    # are candidates. There is no owner=/user= kwarg, so the rule flags it.
    # todook: thiagoteixeira.django.security.idor.object-lookup-without-owner-scope
    return get_object_or_404(request.user.notes, pk=pk)


def false_positive_prefiltered_queryset(request, pk):
    # Scoped by a queryset filtered before the call. The owner= sits inside the
    # first argument, not on the shortcut, so the rule flags it.
    # todook: thiagoteixeira.django.security.idor.object-lookup-without-owner-scope
    return get_object_or_404(Note.objects.filter(owner=request.user), pk=pk)


def false_positive_public_object(request, slug):
    # A published post is public by design; nobody owns it in the IDOR sense.
    # The rule has no notion of public objects, so it flags it.
    # todook: thiagoteixeira.django.security.idor.object-lookup-without-owner-scope
    return get_object_or_404(Post, slug=slug, published=True)


def known_miss_attacker_chosen_user(request, pk):
    # The user= kwarg is present, but its value comes from the request, so the
    # caller picks whose profile to read. The rule checks the kwarg, not its value.
    # todoruleid: thiagoteixeira.django.security.idor.object-lookup-without-owner-scope
    return get_object_or_404(Profile, pk=pk, user=request.GET["uid"])


class KnownMissUnscopedDrfQueryset(viewsets.ModelViewSet):
    # The post's Pattern 2: an unscoped DRF queryset. No shortcut call, no match.
    # todoruleid: thiagoteixeira.django.security.idor.object-lookup-without-owner-scope
    queryset = Document.objects.all()
