"""Sample data and the CTF flag for Lab 12. Run via `manage.py seed_labs`.

Seeds the shared cast (alice, bob). *bob* is the victim; his private secret holds
the flag. The exploit fixes a session id onto bob's login through the vulnerable
view, then reads this secret from that same (never-rotated) session — so
capturing the flag *is* the session fixation. Idempotent.
"""

from labs._common.users import seed_users

from .models import Secret

FLAG = "FLAG{session_fixation_rode_the_unrotated_session}"


def seed():
    users = seed_users()
    bob = users["bob"]  # the victim
    Secret.objects.filter(owner=bob).delete()
    Secret.objects.create(owner=bob, body=f"private: {FLAG}")
    return "seeded cast + bob's flagged secret (victim='bob')"
