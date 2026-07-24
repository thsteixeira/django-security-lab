"""Sample data and the CTF flag for Lab 02. Run via `manage.py seed_labs`."""

from .models import Comment, Flag

FLAG = "FLAG{xss_via_mark_safe_without_sanitisation}"


def seed():
    """Plant two benign comments and the session-token flag. Idempotent."""
    Comment.objects.all().delete()
    Flag.objects.all().delete()
    Comment.objects.bulk_create(
        [
            Comment(author="alice", body="Great write-up — thanks!"),
            Comment(author="bob", body="Works for me on <strong>Django 5.2</strong>."),
        ]
    )
    Flag.objects.create(value=FLAG)
    return "seeded 2 comments and the CTF flag"
