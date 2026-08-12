"""Filesystem layout for the XXE lab.

Like the path-traversal lab, the state under study is the filesystem: the flag
is an off-limits file that only the XML External Entity read reaches. There is no
model — `seed.py` plants the flag file (a documented deviation from the fixed
skeleton; see README.md).

The tree lives under the system temp dir so it is writable everywhere the tests
run: the non-root `web` container (where /app is read-only), the native CI runner
(which runs `manage.py test` directly, not in the image), and a local checkout.

    <tempdir>/xxe/flag.txt   <- read by <!ENTITY xxe SYSTEM "file://…/flag.txt">

The webhook has no legitimate reason to read this file; only an external-entity
payload, resolved by an unhardened parser, does. It stands in for the local file
(settings.py, /etc/passwd) the real attack discloses.
"""
import tempfile
from pathlib import Path

XXE_ROOT = Path(tempfile.gettempdir()) / "xxe"
FLAG_PATH = XXE_ROOT / "flag.txt"


def ensure_layout(flag_value):
    """Create the off-limits flag file. Idempotent — safe to call from both the
    seed and each test's setUp."""
    XXE_ROOT.mkdir(parents=True, exist_ok=True)
    FLAG_PATH.write_text(flag_value + "\n")


def flag_file_uri():
    """The file:// URI the XXE payload points its external entity at.
    In the Linux container this is file:///tmp/xxe/flag.txt."""
    return FLAG_PATH.as_uri()
