"""Run the wrap data migration on demand, for rows seeded after ``migrate``."""

from django.apps import apps
from django.core.management.base import BaseCommand

from labs.post_18_password_hashing.wrap import wrap_sha1_hashes


class Command(BaseCommand):
    help = "Wrap every bare SHA-1 password row in PBKDF2 (Lab 18's data migration)."

    def handle(self, *args, **options):
        wrapped = wrap_sha1_hashes(apps)
        self.stdout.write(f"wrapped {wrapped} SHA-1 row(s) in PBKDF2\n")
