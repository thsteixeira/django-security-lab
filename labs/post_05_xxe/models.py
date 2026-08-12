"""No model — a deliberate, documented deviation from the fixed skeleton.

The state under study in an XXE lab is what the parser reads off the filesystem,
not a database row, so there is nothing to model. `_fs.py` owns the flag file and
`seed.py` plants it. This file is intentionally empty of models so the app label
(`xxe`) still registers and the module reads like every other lab. See README.md
("Isolation") for why this shape fits the class.
"""
