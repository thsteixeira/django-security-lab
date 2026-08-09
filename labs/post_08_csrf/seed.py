"""Sample data and the CTF flag for Lab 08. Run via `manage.py seed_labs`.

alice is the *victim* — she is logged in and holds the flag. bob is the
*attacker* — his account starts empty and receives the flag if a forged,
tokenless transfer succeeds. Idempotent.
"""

from labs._common.users import seed_users

from .models import Account

FLAG = "FLAG{csrf_via_csrf_exempt_state_change}"


def seed():
    users = seed_users()
    Account.objects.all().delete()
    Account.objects.create(user=users["alice"], holdings=FLAG)  # victim holds the flag
    Account.objects.create(user=users["bob"], holdings="")       # attacker's account
    return "seeded accounts — alice (victim) holds the flag, bob (attacker) empty"
