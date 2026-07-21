from django.db import models


class Note(models.Model):
    """Public, searchable notes. The vulnerable search view queries this table."""

    title = models.CharField(max_length=200)
    body = models.TextField()

    class Meta:
        db_table = "sqli_note"

    def __str__(self):
        return self.title


class Flag(models.Model):
    """The CTF secret. The search feature is NOT supposed to reach this table.

    A SQL-injection UNION payload against the vulnerable view can pull rows out
    of it anyway — capturing the flag proves the injection worked.
    """

    value = models.CharField(max_length=200)

    class Meta:
        db_table = "sqli_flag"

    def __str__(self):
        return self.value
