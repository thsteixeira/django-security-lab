"""Sample data and the CTF flag for Lab 05. Run via `manage.py seed_labs`.

Plants a file, not a row — the lab has no model (see models.py). Writes the
off-limits flag file that only the external-entity read reaches.
"""
from ._fs import FLAG_PATH, ensure_layout

FLAG = "FLAG{xxe_external_entity_file_read}"


def seed():
    ensure_layout(FLAG)
    return f"xxe: wrote off-limits flag ({FLAG_PATH})"
