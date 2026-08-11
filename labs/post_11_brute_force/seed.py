"""Sample data and the CTF flag for Lab 11. Run via `manage.py seed_labs`.

Seeds a dedicated `victim` with a **deliberately weak** password that sits in the
demo wordlist, and a private note holding the flag. The password is weak on
purpose — the lab is about *rate*, not password strength (hashing is Post 18,
policy is Post 13). Idempotent.
"""

from django.contrib.auth.models import User

from .models import Note

FLAG = "FLAG{brute_force_ip_ratelimit_bypassed}"
VICTIM = "victim"
VICTIM_PASSWORD = "summer2024"  # deliberately weak — last entry of WORDLIST below

# The attacker's tiny wordlist. The victim's real password is the LAST entry, so a
# per-account lockout (limit 5) blocks the secure login before it is ever reached;
# the vulnerable login, bypassed by rotating X-Forwarded-For, walks all the way to it.
WORDLIST = ["123456", "password", "qwerty", "letmein", "iloveyou", "admin", VICTIM_PASSWORD]


def seed():
    victim, _ = User.objects.get_or_create(username=VICTIM)
    victim.set_password(VICTIM_PASSWORD)
    victim.save()
    Note.objects.filter(owner=victim).delete()
    Note.objects.create(owner=victim, body=f"private: {FLAG}")
    return f"seeded victim '{VICTIM}' (weak password) + flag note"
