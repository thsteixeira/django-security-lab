# The data migration a real project ships with PBKDF2WrappedSHA1PasswordHasher:
# every bare SHA-1 digest in auth_user becomes a salted PBKDF2 row. See wrap.py for
# why, in this lab, it usually finds nothing to wrap and has a management command
# twin.
from django.db import migrations

from labs.post_18_password_hashing.wrap import wrap_sha1_hashes


class Migration(migrations.Migration):

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        ("passwordhashing", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(wrap_sha1_hashes, migrations.RunPython.noop),
    ]
