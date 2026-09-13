"""Two blocklist validators — the control NIST SP 800-63B-4 §3.1.1.2 actually
requires ("verifiers SHALL compare the prospective secret against a blocklist
that contains known commonly used, expected, or compromised passwords").

Django ships ``CommonPasswordValidator`` with a 19,640-entry list. That is a good
list and a small one. These two extend it in the two directions that matter:

``BreachListValidator``
    Offline, from a gzipped file you control. This is the one wired into
    ``AUTH_PASSWORD_VALIDATORS`` in config/settings.py, so the lab, the test
    suite and CI never depend on a third party being reachable. Its shipped file
    holds the composition-rule survivors Django's list misses (``password123!``,
    ``summer2026!``) plus the site-specific terms no generic wordlist will ever
    contain (your brand, your domain, this year).

``PwnedPasswordValidator``
    Online, against the Have I Been Pwned corpus, via the k-anonymity range API:
    only the first five hex characters of the SHA-1 leave this process, and the
    final comparison happens locally. This is the production-grade version. It is
    NOT in the active stack — a lab whose tests hit the public internet is a lab
    that goes red when someone else has an outage — but it is real, runnable code
    and ``tests.py`` exercises it against a stubbed transport.

Standard library only: ``urllib.request`` rather than ``httpx``/``requests``, so
this lab adds no dependency and the code is copy-pasteable into any Django
project without one.
"""

import gzip
import hashlib
import urllib.error
import urllib.request
from pathlib import Path

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

DEFAULT_LIST_PATH = Path(__file__).resolve().parent / "data" / "breach-list.txt.gz"

RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


class BreachListValidator:
    """Reject passwords present in a local gzipped blocklist.

    Deliberately mirrors Django's own ``CommonPasswordValidator``: the file is
    read once at construction into a set, and the comparison is against
    ``password.lower().strip()``, so the file must be lowercased.
    """

    def __init__(self, password_list_path=DEFAULT_LIST_PATH):
        with gzip.open(password_list_path, "rt", encoding="utf-8") as fh:
            self.passwords = {line.strip() for line in fh if line.strip()}

    def validate(self, password, user=None):
        if password.lower().strip() in self.passwords:
            raise ValidationError(
                _("This password has appeared in a known data breach and cannot be used."),
                code="password_pwned",
            )

    def get_help_text(self):
        return _("Your password can't be one that has appeared in a data breach.")


class PwnedPasswordValidator:
    """Reject passwords that appear in the Have I Been Pwned breach corpus.

    Uses the k-anonymity range API: only the first 5 characters of the SHA-1
    hash leave this process. The password itself is never transmitted.
    """

    def __init__(self, threshold=1, timeout=2.0, fail_open=True):
        self.threshold = threshold
        self.timeout = timeout
        self.fail_open = fail_open

    def _fetch(self, prefix):
        """Return the API's raw suffix:count body for one 5-character bucket.

        Split out so tests can stub the network without stubbing the validator's
        actual logic (the parsing and the threshold comparison stay under test).
        """
        request = urllib.request.Request(
            RANGE_URL.format(prefix=prefix),
            # Pads the response with random suffixes so an observer cannot infer
            # the bucket size — and therefore narrow the password — from the
            # encrypted response length. Costs the CDN cache: Cache-Control
            # comes back "no-store" instead of "public, max-age=2678400".
            headers={"Add-Padding": "true"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return response.read().decode("utf-8")

    def validate(self, password, user=None):
        # SHA-1 is not a choice here — it is the wire format the range API
        # defines, and it is used as a lookup key into a public corpus, not to
        # protect anything. `usedforsecurity=False` says exactly that: it keeps
        # the call working on FIPS-restricted builds, and it is what stops
        # Bandit's B324 from flagging this line (see scans/README.md).
        digest = hashlib.sha1(
            password.encode("utf-8"), usedforsecurity=False
        ).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]

        try:
            body = self._fetch(prefix)
        except (urllib.error.URLError, OSError):
            if self.fail_open:
                # Availability over policy: a HIBP outage must not take every
                # registration and password reset on the site down with it. The
                # opposite choice is defensible for high-assurance systems —
                # make it deliberately, and write down which one you picked.
                return
            raise ValidationError(
                _("Could not verify this password against the breach database. "
                  "Please try again."),
                code="pwned_check_unavailable",
            )

        for line in body.splitlines():
            candidate_suffix, _sep, count = line.partition(":")
            if candidate_suffix == suffix and int(count or 0) >= self.threshold:
                raise ValidationError(
                    _("This password has appeared in a known data breach and cannot be used."),
                    code="password_pwned",
                )

    def get_help_text(self):
        return _("Your password can't be one that has appeared in a data breach.")
