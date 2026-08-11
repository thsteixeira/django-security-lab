"""VULNERABLE upload-inspector — do NOT copy this into real code.

It shells out to `wc -c <name>` with `shell=True` and the user-supplied filename
interpolated straight into the command string, so shell metacharacters in `name`
run as commands. The payload `sample.txt; cat ../flag.txt` makes the shell run a
*second* command that reads the flag file one directory above uploads/ — data the
"inspect an upload" feature has no business touching.

⚠️ TIER 3 — this view executes attacker-controlled shell commands (real RCE).
Run it only inside the provided Docker stack, where `web` is non-root and has no
network egress (see SECURITY.md).

CI scans this file with Bandit and asserts B602 (subprocess with shell=True)
fires here and stays silent on views_secure.py.
"""
import subprocess

from django.http import HttpResponse
from django.utils.html import escape

from ._fs import UPLOAD_DIR
from .models import Upload


def inspect(request):
    if request.method != "POST":
        return HttpResponse(
            "<h1>Vulnerable upload inspector</h1>"
            "<p>POST a <code>name</code> to run <code>wc -c &lt;name&gt;</code> on it.</p>"
        )

    name = request.POST.get("name", "")
    Upload.objects.create(name=name)

    # DANGER: user input interpolated into a shell command string. Bandit B602
    # flags shell=True here. `name=sample.txt; cat ../flag.txt` runs a second
    # command (cwd is uploads/, so ../flag.txt is the off-limits flag file).
    result = subprocess.run(
        f"wc -c {name}",
        shell=True,
        cwd=str(UPLOAD_DIR),
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    return HttpResponse(
        f"<h1>Vulnerable upload inspector</h1><pre>{escape(output)}</pre>"
    )
