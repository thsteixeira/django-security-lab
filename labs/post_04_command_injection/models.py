from django.db import models


class Upload(models.Model):
    """A thin record that a file was submitted for inspection.

    The interesting state in this lab is on disk (uploads/ and the off-limits
    flag file), not here — this table just shows the feature ran.
    """

    name = models.CharField(max_length=255)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "cmdinj_upload"

    def __str__(self):
        return self.name
