"""Filesystem layout for the path-traversal lab.

The lab's state is the filesystem, not a database table — that is the honest
shape for this class, so this lab has no model (a documented deviation from the
fixed skeleton; see README.md). `seed()` plants files instead of rows.

The tree lives under the system temp dir so it is writable everywhere the tests
run: the non-root `web` container (where /app is read-only), the native CI runner
(which runs `manage.py test` directly, not in the image), and a local checkout.

    <tempdir>/traversal/
    ├── flag.txt          <- OFF-LIMITS, one level ABOVE the served root
    └── documents/        <- DOCS_ROOT: the only directory the view should serve
        └── readme.txt    <- a legitimate document

The view is meant to serve files from documents/ only. `flag.txt` sits one level
ABOVE it, so the download feature has no legitimate way to reach it. Only a
traversal payload — `../flag.txt`, or an absolute path — escapes DOCS_ROOT and
reads it. This mirrors the post's MEDIA_ROOT / settings.py shape: the flag stands
in for the secret the real attack reads above the media directory.
"""
import tempfile
from pathlib import Path

TRAVERSAL_ROOT = Path(tempfile.gettempdir()) / "traversal"
DOCS_ROOT = TRAVERSAL_ROOT / "documents"     # the served document root
FLAG_PATH = TRAVERSAL_ROOT / "flag.txt"      # parent of documents/ -> reached via ../flag.txt

README_NAME = "readme.txt"
README_BODY = "Public document. Nothing secret here.\n"


def ensure_layout(flag_value):
    """Create documents/, a legitimate file to serve, and the off-limits flag
    file one level above it. Idempotent — safe to call from both the seed and
    each test's setUp."""
    DOCS_ROOT.mkdir(parents=True, exist_ok=True)
    (DOCS_ROOT / README_NAME).write_text(README_BODY)
    FLAG_PATH.write_text(flag_value + "\n")
