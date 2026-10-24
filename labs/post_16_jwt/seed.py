"""Sample data and the CTF flag for Lab 16. Run via ``manage.py seed_labs``.

The standard cast (B7): ``alice`` is the attacker, ``bob`` the victim. Both log
in with the shared lab password and get real tokens from ``/jwt/token/``. bob's
export holds the flag; alice's holds nothing worth stealing.

The attacker never learns bob's password. All she needs is bob's user id, which
the seed log prints, because the vulnerable view takes the id from a payload she
writes herself. On the secure view the same payload needs a signature only the
project's signing key can produce.

Idempotent. Re-running restores both users' passwords and both exports.
"""

from labs._common.users import seed_users

from .models import ExportRecord

FLAG = "FLAG{jwt_claims_trusted_without_signature_check}"


def seed():
    users = seed_users()
    alice, bob = users["alice"], users["bob"]

    ExportRecord.objects.filter(owner__in=[alice, bob]).delete()
    ExportRecord.objects.create(owner=alice, body="3 invoices, all paid")
    ExportRecord.objects.create(owner=bob, body=f"payroll export: {FLAG}")

    return (
        f"seeded alice (attacker, user_id {alice.pk}) + bob (victim, user_id "
        f"{bob.pk}) — bob's export holds the flag"
    )
