"""Fixture for rules/mass_assignment.yaml — paired by filename stem for
`semgrep --test`.

Mirrors the Lab 07 forms: a Meta with fields = "__all__" (the mass-assignment
sink) vs. an explicit allowlist. Also shows the DRF ModelSerializer shape the
rule covers for Wave 5, the other spellings of "every field" it also catches
(ALL_FIELDS, an empty exclude, modelform_factory), and its two limits: the
non-empty `exclude` gap (todoruleid) and the django-filter FilterSet false
positive (todook). This file is parsed by semgrep, never executed, so the
imports need not resolve at runtime.
"""
import django_filters
from django import forms
from django.forms import modelform_factory
from django.forms.models import ALL_FIELDS
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


class FooFormAllFieldsConstant(forms.ModelForm):
    class Meta:
        model = Foo
        # Django's own constant for "__all__"
        # ruleid: thiagoteixeira.django.security.mass-assignment.model-fields-all
        fields = ALL_FIELDS


class FooFormEmptyExclude(forms.ModelForm):
    class Meta:
        model = Foo
        # an empty exclude binds every field, exactly like "__all__"
        # ruleid: thiagoteixeira.django.security.mass-assignment.model-fields-all
        exclude = []


# ruleid: thiagoteixeira.django.security.mass-assignment.model-fields-all
FooFactoryForm = modelform_factory(Foo, fields="__all__")


class FooFilter(django_filters.FilterSet):
    class Meta:
        model = Foo
        # A FilterSet Meta lists filter fields, not writable ones; the rule
        # cannot tell the two Metas apart - a known false positive, hence todook.
        # todook: thiagoteixeira.django.security.mass-assignment.model-fields-all
        fields = "__all__"
