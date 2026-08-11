"""No model — a deliberate, documented deviation from the fixed skeleton.

The state under study in a path-traversal lab is the *filesystem*, not a
database row, so there is nothing to model. `_fs.py` owns the on-disk layout and
`seed.py` plants files instead of rows. This file is intentionally empty of
models so the app label (`traversal`) still registers and the module reads like
every other lab. See README.md ("Isolation") for why this shape is the honest
one for the class.
"""
