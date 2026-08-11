"""Filesystem layout for the command-injection lab.

The lab writes a small tree at runtime — an uploads/ directory to inspect and an
off-limits flag file one level above it. It lives under the system temp dir so it
is writable everywhere the tests run: the non-root `web` container (where /app is
read-only), the native CI runner (which runs `manage.py test` directly, not in
the image), and a local checkout.

The flag sits one level ABOVE uploads/, so the inspector — which only ever runs
`wc -c` inside uploads/ — has no legitimate way to reach it. Only the injection,
which escapes that command, reads `../flag.txt`.
"""
import tempfile
from pathlib import Path

CMDINJ_ROOT = Path(tempfile.gettempdir()) / "cmdinj"
UPLOAD_DIR = CMDINJ_ROOT / "uploads"        # the inspector's working directory
FLAG_PATH = CMDINJ_ROOT / "flag.txt"        # parent of uploads/ -> reached via ../flag.txt

SAMPLE_NAME = "sample.txt"
SAMPLE_BODY = "hello, command-injection lab\n"


def ensure_layout(flag_value):
    """Create uploads/, a sample file to inspect, and the off-limits flag file.
    Idempotent — safe to call from both the seed and each test's setUp."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    (UPLOAD_DIR / SAMPLE_NAME).write_text(SAMPLE_BODY)
    FLAG_PATH.write_text(flag_value + "\n")
