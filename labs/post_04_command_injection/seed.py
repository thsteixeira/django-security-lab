"""Sample data and the CTF flag for Lab 04. Run via `manage.py seed_labs`.

Writes the on-disk layout the inspector reads (uploads/sample.txt) and the flag
file one level above it, then records a marker row. The flag lives on disk,
outside uploads/, where only the command injection can reach it.
"""
from ._fs import FLAG_PATH, SAMPLE_NAME, ensure_layout
from .models import Upload

FLAG = "FLAG{command_injection_via_shell_true}"


def seed():
    ensure_layout(FLAG)
    Upload.objects.all().delete()
    Upload.objects.create(name=SAMPLE_NAME)
    return f"cmdinj: wrote uploads/ + off-limits flag ({FLAG_PATH}), seeded 1 upload record"
