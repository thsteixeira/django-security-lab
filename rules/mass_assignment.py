"""Fixture for rules/mass_assignment.yaml — paired by filename stem for
`semgrep --test`.

Mirrors the Lab 07 forms: a Meta with fields = "__all__" (the mass-assignment
sink) vs. an explicit allowlist. Also shows the DRF ModelSerializer shape the
rule covers for Wave 5, and documents the `exclude` gap. This file is parsed by
semgrep, never executed, so the imports need not resolve at runtime.
"""
from django import forms
from rest_framework import serializers

from .models import Foo


class FooFormBad(forms.ModelForm):
    class Meta:
        model = Foo
        # ruleid: thiagoteixeira.django.security.mass-assignment.model-fields-all
        fields = "__all__"


class FooFormGood(forms.ModelForm):
    class Meta:
        model = Foo
        # ok: thiagoteixeira.django.security.mass-assignment.model-fields-all
        fields = ["display_name", "bio"]


class FooSerializerBad(serializers.ModelSerializer):
    class Meta:
        model = Foo
        # single quotes must fire too
        # ruleid: thiagoteixeira.django.security.mass-assignment.model-fields-all
        fields = '__all__'


class FooFormExcludeVariant(forms.ModelForm):
    class Meta:
        model = Foo
        # The `exclude` denylist is a related but distinct antipattern (new model
        # fields silently become writable); this rule targets fields="__all__"
        # only, so it does not fire here — a documented scope limit.
        # todoruleid: thiagoteixeira.django.security.mass-assignment.model-fields-all
        exclude = ["role"]
