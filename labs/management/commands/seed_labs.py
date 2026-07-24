"""Seed every lab in one command.

Each lab ships a `seed.py` exposing an idempotent `seed()` that plants that
lab's sample data and its CTF flag. Discovery lives here rather than in a
per-lab `seed_lab` command because Django resolves duplicate management-command
names to a single winner — with more than one lab, only one would ever run.
"""

from importlib import import_module

from django.apps import apps
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Seed every lab with its sample data and CTF flag (idempotent)."

    def handle(self, *args, **options):
        seeded = 0
        for app_config in apps.get_app_configs():
            if not app_config.name.startswith("labs.post_"):
                continue
            try:
                module = import_module(f"{app_config.name}.seed")
            except ModuleNotFoundError:
                self.stderr.write(f"{app_config.label}: no seed.py — skipped")
                continue
            self.stdout.write(self.style.SUCCESS(f"{app_config.label}: {module.seed()}"))
            seeded += 1

        if not seeded:
            self.stderr.write("No labs found to seed.")
