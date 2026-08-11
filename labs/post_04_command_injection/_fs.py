"""Filesystem layout for the command-injection lab.

`/app` is read-only to the non-root `labuser` (B6, tier-3 containment), so the
lab's writable data lives under `/data` (created and chowned to labuser in the
Dockerfile). The flag file sits one level ABOVE the upload directory: no
legitimate code path — which only ever runs `wc -c` inside uploads/ — can reach
it. Only the injection, which escapes that command, reads `../flag.txt`.
"""
from pathlib import Path

CMDINJ_ROOT = Path("/data/cmdinj")
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
