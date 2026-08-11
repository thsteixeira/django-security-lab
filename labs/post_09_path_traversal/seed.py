"""Sample data and the CTF flag for Lab 09. Run via `manage.py seed_labs`.

Plants files, not rows — the lab has no model (see models.py). Writes a
legitimate document inside the served root (documents/readme.txt) and the
off-limits flag file one level above it, where only a traversal payload reaches.
"""
from ._fs import FLAG_PATH, ensure_layout

FLAG = "FLAG{path_traversal_via_unvalidated_path_join}"


def seed():
    ensure_layout(FLAG)
    return f"traversal: wrote documents/readme.txt + off-limits flag ({FLAG_PATH})"
