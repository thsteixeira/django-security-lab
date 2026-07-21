---
name: Scanner false positive / false negative
about: A scanner fires on safe lab code, or misses a vulnerable pattern
title: "[scan] "
labels: scan
---

**Tool**
e.g. Bandit, Semgrep (`p/django`), pip-audit, sqlmap — and the rule id / check if
you have it.

**Which lab / file**
e.g. `labs/post_01_sql_injection/views_vulnerable.py`

**Which is it?**
- [ ] False positive — the tool fired on code that is actually safe
- [ ] False negative — the tool missed a genuinely vulnerable pattern

**Command + output**
```
# the exact command you ran and what it reported
```

**Expected vs actual**
What should the scanner have done, and what did it do?

**Notes**
Is this already documented as a known limitation in the lab README's scanning
section? (If so, it may be an accepted trade-off rather than a bug.)
