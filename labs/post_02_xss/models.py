from django.db import models


class Comment(models.Model):
    """A user-submitted comment. `body` is untrusted HTML, on purpose.

    Rich-text comment fields are the ordinary reason an application ends up
    calling mark_safe() on user input at all — the vulnerable view does exactly
    that with no sanitiser in between.
    """

    author = models.CharField(max_length=80)
    body = models.TextField()

    class Meta:
        db_table = "xss_comment"

    def __str__(self):
        return f"{self.author}: {self.body[:40]}"


class Flag(models.Model):
    """The CTF secret, rendered into the page as the visitor's session token.

    Nothing the comment feature does is supposed to hand this to another user.
    But an injected script runs inside the page's own origin, so it can read the
    value straight out of the DOM — which is what makes XSS an access-control
    failure and not just a rendering bug.
    """

    value = models.CharField(max_length=200)

    class Meta:
        db_table = "xss_flag"

    def __str__(self):
        return self.value
