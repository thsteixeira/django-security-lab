"""The standard user cast the authenticated labs share (B7).

One place creates ``alice`` and ``bob`` so eight labs do not each invent their
own users. The *roles* are per-lab, matching each post: in the IDOR lab (post 6)
``alice`` is the attacker and ``bob`` the victim who owns the flagged object; in
the CSRF lab (post 8) ``alice`` is the authenticated victim. The names come from
the published posts' own test code, which is the source of truth (§1.2 Step 3).

Labs that need a special account — e.g. the brute-force lab's deliberately weak,
crackable password — create it themselves; this is a convenience, not a mandate.
"""

from django.contrib.auth.models import User

# Every cast member shares one password. It is intentionally not a secret — this
# whole project is intentionally vulnerable and never deployed.
PASSWORD = "labpass"

# username -> email. Roles are assigned per-lab, not here.
CAST = {
    "alice": "alice@example.test",
    "bob": "bob@example.test",
}


def seed_users():
    """Create the standard cast if absent; reset their passwords. Idempotent.

    Returns a dict of ``{username: User}`` so a lab's seed can wire ownership
    (e.g. give ``bob`` the flagged note) without re-querying.
    """
    users = {}
    for username, email in CAST.items():
        user, _ = User.objects.get_or_create(
            username=username, defaults={"email": email}
        )
        user.email = email
        user.set_password(PASSWORD)
        user.save()
        users[username] = user
    return users
