"""Sample data and the CTF flag for Lab 07. Run via `manage.py seed_labs`.

Seeds the shared cast (alice, bob) each with a `member` profile, and the flag
that lives behind the staff gate. Idempotent — reseeding resets any role a
previous exploit escalated back to `member`.
"""

from labs._common.users import seed_users

from .models import Flag, Profile

FLAG = "FLAG{privilege_escalation_via_mass_assignment}"


def seed():
    users = seed_users()

    Profile.objects.all().delete()
    for username, user in users.items():
        Profile.objects.create(
            user=user, display_name=username.capitalize(), role="member"
        )

    Flag.objects.all().delete()
    Flag.objects.create(value=FLAG)

    return "seeded profiles (alice, bob = member) + the staff-area flag"
