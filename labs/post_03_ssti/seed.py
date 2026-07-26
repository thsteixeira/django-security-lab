"""Sample data and the CTF flag for Lab 03. Run via `manage.py seed_labs`."""

from .models import Flag

FLAG = "FLAG{ssti_user_input_compiled_as_template}"


def seed():
    """Plant the CTF flag into the render context's secret slot. Idempotent."""
    Flag.objects.all().delete()
    Flag.objects.create(value=FLAG)
    return "seeded the CTF flag"
