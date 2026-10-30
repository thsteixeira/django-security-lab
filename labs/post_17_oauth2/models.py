from django.contrib.auth.models import User
from django.db import models


class Identity(models.Model):
    """A provider account linked to a local one.

    A row means: whoever signs in at this provider as this subject *is* this local
    user. The secure callback finds accounts only through these rows, keyed on
    (issuer, subject), the only pair OpenID Connect guarantees to be unique and
    stable. A row is created only by the "connect your provider account" flow, for a
    user who is already signed in with their password.
    """

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="oauth2_identities"
    )
    issuer = models.CharField(max_length=200)
    subject = models.CharField(max_length=200)

    class Meta:
        db_table = "oauth2_identity"
        constraints = [
            models.UniqueConstraint(
                fields=["issuer", "subject"], name="oauth2_identity_unique"
            )
        ]

    def __str__(self):
        return f"identity({self.issuer}, {self.subject} -> user {self.user_id})"


class Note(models.Model):
    """A private note, shown only to its owner at /oauth2/account/. alice's holds the flag."""

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="oauth2_notes")
    body = models.TextField()

    class Meta:
        db_table = "oauth2_note"

    def __str__(self):
        return f"note(owner={self.owner_id})"


class ProviderAccount(models.Model):
    """The provider's side: an account at the identity provider.

    ``subject`` never changes. ``email`` is whatever the account holder last typed
    in, and ``email_verified`` records whether the provider ever checked it.
    """

    username = models.CharField(max_length=150, unique=True)
    subject = models.CharField(max_length=200, unique=True)
    email = models.EmailField()
    email_verified = models.BooleanField(default=False)

    class Meta:
        db_table = "oauth2_provideraccount"

    def __str__(self):
        return f"provider_account({self.username}, {self.subject})"


class AuthorizationCode(models.Model):
    """The provider's side: a one-time code, bound to the redirect URI it was issued for."""

    code = models.CharField(max_length=64, unique=True)
    subject = models.CharField(max_length=200)
    redirect_uri = models.CharField(max_length=200)
    used = models.BooleanField(default=False)

    class Meta:
        db_table = "oauth2_authorizationcode"

    def __str__(self):
        return f"code(subject={self.subject}, used={self.used})"
