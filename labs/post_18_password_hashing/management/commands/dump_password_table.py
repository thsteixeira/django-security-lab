"""The leak, given rather than exploited: print the user table as an attacker gets it.

How a password table leaves a company varies — a SQL injection (Lab 1), a backup
left in a bucket, an employee's stolen VPN credentials — and none of it is this
lab's subject. The attack under study starts once the copy exists, so this command
simply produces one: every row of ``auth_user``, username and stored password, as
CSV on stdout. Redirect it to a file, or pipe it straight into ``crack.py``.
"""

import csv

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Print auth_user's username and password columns as CSV (Lab 18's leak)."

    def handle(self, *args, **options):
        writer = csv.writer(self.stdout, lineterminator="\n")
        writer.writerow(["username", "password"])
        for username, password in User.objects.order_by("username").values_list(
            "username", "password"
        ):
            writer.writerow([username, password])
