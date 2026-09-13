"""Sample data and the CTF flag for Lab 13. Run via `manage.py seed_labs`.

Seeds ``carol`` — the victim — with the password ``Password123!``, written the
same way the vulnerable registration view writes it: ``set_password()``, no
validation. That password is not an invention. It satisfies every character-class
rule anyone has ever written, it passes all four of Django's default validators,
and it has been seen 295,389 times in the Have I Been Pwned corpus. It is, in
other words, the single best example of why composition rules do not work.

Carol's private secret holds the flag. Because her password sits near the top of
every real wordlist, an attacker needs **one guess** — no throttle to defeat, no
rate to sustain. That is the whole difference from Lab 11: this lab is about the
password being cheap, not about the guessing being fast.

Lab 11 already owns the username ``victim``, and both seeds run in the same
``seed_labs`` pass, so this lab uses its own account. Idempotent.
"""

from django.contrib.auth.models import User

from .models import Secret

FLAG = "FLAG{one_guess_the_validator_never_ran}"

VICTIM = "carol"
VICTIM_EMAIL = "carol@example.test"

# Passes UserAttributeSimilarity, MinimumLength(8), CommonPassword and
# NumericPassword — Django's four defaults — and appears 295,389 times in HIBP.
VICTIM_PASSWORD = "Password123!"

# A passphrase that clears the hardened stack in config/settings.py: 26 characters,
# in neither blocklist, not numeric, not similar to any user attribute.
STRONG_PASSWORD = "flat marble kettle horizon"


def seed():
    carol, _ = User.objects.get_or_create(
        username=VICTIM, defaults={"email": VICTIM_EMAIL}
    )
    carol.email = VICTIM_EMAIL
    # Exactly what views_vulnerable.register() does: hashed, never validated.
    carol.set_password(VICTIM_PASSWORD)
    carol.save()

    Secret.objects.filter(owner=carol).delete()
    Secret.objects.create(owner=carol, body=f"private: {FLAG}")

    return f"seeded victim '{VICTIM}' (password accepted by Django's defaults) + flag secret"
