"""SECURE upload-inspector — the same feature, done safely.

The filename never reaches a shell. `subprocess.run([...], shell=False)` passes
`name` to `wc` as a single argument, so shell metacharacters are inert: the
payload `sample.txt; cat ../flag.txt` is treated as one (nonexistent) filename and
`wc` simply reports it does not exist. A legitimate filename still returns its
byte count, so the feature still works.

No shell is invoked, so Bandit's B602 (shell=True) stays silent here — CI asserts
exactly that. Bandit's B603 is a low-severity note that fires on *any* subprocess
call, safe or not; it is not a shell-injection finding (see scans/README.md).
"""
import os
import subprocess

from django.http import HttpResponse
from django.utils.html import escape

from ._fs import UPLOAD_DIR
from .models import Upload


def inspect(request):
    if request.method != "POST":
        return HttpResponse(
            "<h1>Secure upload inspector</h1>"
            "<p>POST a <code>name</code> to run <code>wc -c &lt;name&gt;</code> on it.</p>"
        )

    name = request.POST.get("name", "")
    Upload.objects.create(name=name)

    # SAFE: the filename is one argument in the list, never part of a shell
    # string. No metacharacter can start a second command; a payload just names a
    # file that does not exist, and wc says so.
    path = os.path.join(str(UPLOAD_DIR), name)
    result = subprocess.run(
        ["wc", "-c", path],
        shell=False,
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    return HttpResponse(
        f"<h1>Secure upload inspector</h1><pre>{escape(output)}</pre>"
    )
