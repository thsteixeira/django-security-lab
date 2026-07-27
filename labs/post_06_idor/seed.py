"""Sample data and the CTF flag for Lab 06. Run via `manage.py seed_labs`.

Seeds the shared cast (alice, bob) and one note each. The flag lives in *bob*'s
note; *alice* is the attacker who reads it through the unscoped lookup. The
return string reports both notes' primary keys so you know what to curl.
"""

from labs._common.users import seed_users

from .models import Note

FLAG = "FLAG{idor_via_unscoped_object_lookup}"


def seed():
    """Plant the cast and their notes; the flag sits in bob's note. Idempotent."""
    users = seed_users()
    alice, bob = users["alice"], users["bob"]

    Note.objects.all().delete()
    alice_note = Note.objects.create(
        owner=alice,
        title="Alice's grocery list",
        body="milk, eggs, bread",
    )
    bob_note = Note.objects.create(
        owner=bob,
        title="Bob's private note",
        body=f"Do not share this: {FLAG}",
    )
    return (
        f"seeded cast + notes — alice's note pk={alice_note.pk}, "
        f"bob's flagged note pk={bob_note.pk}"
    )
