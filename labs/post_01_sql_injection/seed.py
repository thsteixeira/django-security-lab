"""Sample data and the CTF flag for Lab 01. Run via `manage.py seed_labs`."""

from .models import Flag, Note

FLAG = "FLAG{sql_injection_via_raw_string_interpolation}"


def seed():
    """Plant the searchable notes and the off-limits flag row. Idempotent."""
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
    return "seeded 3 notes and the CTF flag"
