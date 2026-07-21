from django.core.management.base import BaseCommand

from labs.post_01_sql_injection.models import Flag, Note

FLAG = "FLAG{sql_injection_via_raw_string_interpolation}"


class Command(BaseCommand):
    help = "Seed the SQL-injection lab with sample notes and the CTF flag."

    def handle(self, *args, **options):
        Note.objects.all().delete()
        Flag.objects.all().delete()
        Note.objects.bulk_create(
            [
                Note(title="Welcome", body="Public note — search me."),
                Note(title="Release notes", body="Version 1 shipped."),
                Note(title="Standup", body="Daily meeting at 10:00."),
            ]
        )
        Flag.objects.create(value=FLAG)
        self.stdout.write(self.style.SUCCESS("Seeded the SQL-injection lab."))
