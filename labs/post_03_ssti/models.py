from django.db import models


class Flag(models.Model):
    """The CTF secret, placed in the render context under a key the greeting
    feature was never meant to expose.

    SSTI's payoff in a restricted engine like Django's DTL is not RCE — the
    parser refuses to evaluate expressions — but *context disclosure*: reading a
    value like this straight out of the context the view passed in. The flag is
    the context variable the injected template reads.
    """

    value = models.CharField(max_length=200)

    class Meta:
        db_table = "ssti_flag"

    def __str__(self):
        return self.value
