# Lab 05 — XXE (XML External Entity)

Companion lab for the blog post
**[XXE and XML Bombs](https://thiagoteixeira.tech/blog/xxe-and-xml-bombs-why-you-should-think-twice-before-parsing-xml-in-python/)**
(Series I).

| | |
|---|---|
| **OWASP** | A05:2021 — Security Misconfiguration |
| **CWE** | CWE-611 (XML External Entity Reference) · CWE-776 (Recursive Entity Expansion) |
| **ASVS** | V5.5.2 — the XML parser is configured to disable external entity and DTD processing |
| **Detection** | SAST — the standard tools **miss** the lxml parse (Bandit's lxml check `B410` was removed; Semgrep community + registry are 0), so a **custom rule** ([`rules/xxe.yaml`](../../rules/xxe.yaml)) flags the lxml footgun, asserted in the hermetic CI job |

## The two views

An XML webhook that reads an `<order><orderId>…</orderId></order>` document and
echoes the order id back.

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | `lxml.etree.fromstring(request.body, parser=etree.XMLParser(resolve_entities=True))` |
| Secure | [`views_secure.py`](views_secure.py) | `defusedxml.ElementTree.fromstring(request.body)` → 400 on any DTD/entity |

The vulnerable parser resolves entities, so a document that declares an external
entity pointing at a `file://` URI makes the parser read that file and inline it
into `orderId`. The flag lives in `flag.txt` under the system temp dir — the
webhook has no legitimate reason to read it; only the external entity does. The
secure view routes the same body through `defusedxml`, which forbids DTDs and
entities and raises `EntitiesForbidden` before any file is read.

`defusedxml.ElementTree` is the post's Rule 1 headline fix. (defusedxml also
shipped an `lxml` shim, but it is **deprecated** and slated for removal, so the
maintained `ElementTree` shim is the right choice — and the lab uses **lxml** on
the vulnerable side precisely because modern stdlib ElementTree no longer resolves
external entities, so it could not perform the file read.)

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
docker compose exec web python manage.py seed_labs   # plants the off-limits flag
```

On Windows PowerShell `curl` is an alias for `Invoke-WebRequest` — use `curl.exe`,
or Git Bash.

## Test the pair from the command line

**1. Read a local file** — the external entity points at the off-limits flag (in
the container the temp dir is `/tmp`, so the flag is `/tmp/xxe/flag.txt`):

```bash
curl -s -X POST http://127.0.0.1:8000/xxe/vulnerable/ \
  -H "Content-Type: application/xml" \
  --data-binary '<?xml version="1.0"?>
<!DOCTYPE order [ <!ENTITY xxe SYSTEM "file:///tmp/xxe/flag.txt"> ]>
<order><orderId>&xxe;</orderId></order>'
# {"received": "FLAG{xxe_external_entity_file_read}"}
```

**2. The fix holds** — the same payload against the secure view is rejected before
any file is read:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8000/xxe/secure/ \
  -H "Content-Type: application/xml" \
  --data-binary '<?xml version="1.0"?>
<!DOCTYPE order [ <!ENTITY xxe SYSTEM "file:///tmp/xxe/flag.txt"> ]>
<order><orderId>&xxe;</orderId></order>'
# 400
```

**3. The feature still works** — a legitimate order (no entities) parses on both:

```bash
curl -s -X POST http://127.0.0.1:8000/xxe/secure/ \
  -H "Content-Type: application/xml" \
  --data-binary '<order><orderId>A-100</orderId></order>'
# {"received": "A-100"}
```

Or prove all of it in one command (from the repo root):

```bash
docker compose run --rm web python manage.py test labs.post_05_xxe
```

## The fix

Never parse untrusted XML with a stock parser. Route every parse through
`defusedxml`, which forbids DTDs and entity resolution by default:

```python
import defusedxml.ElementTree as ET
from defusedxml.common import EntitiesForbidden, DTDForbidden

try:
    root = ET.fromstring(request.body)
except (EntitiesForbidden, DTDForbidden):
    return HttpResponse(status=400)
```

If a library forces you to hand it a real `lxml` parser, build a locked-down one
(`resolve_entities=False, no_network=True, load_dtd=False`) and reject any
document that carried a DOCTYPE. And cap the size of anything you parse — entity
expansion (Billion Laughs) is a resource-exhaustion attack.

## Isolation

This lab teaches XXE and nothing else. The `file://` read is confined to files the
non-root `web` user can read. The `http://169.254.169.254/` **SSRF-to-metadata**
escalation the post describes is **neutralised by B6**: `web` has no network
egress, so the external-entity fetch of a URL fails — the file-read variant is the
one demonstrated here. There is no model; the state under study is the flag file
the parser reads, so `seed.py` plants a file, not a row (a documented deviation).

## Scanning it

XXE is a textbook class, yet the standard tools miss **this** parse — and *which*
parser they miss is the lesson. Full evidence and reproduction under
[`scans/`](scans/) and [`scans/README.md`](scans/README.md).

```bash
bandit -r labs/post_05_xxe/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_05_xxe/
semgrep scan --config rules/xxe.yaml labs/post_05_xxe/views_vulnerable.py
```

- **Bandit** → **0/0.** Its XML checks are name-based and target the **stdlib**
  (`B405`/`B314` fire on `xml.etree`), but its lxml check `B410` was **removed**
  (`Unknown test found in profile: B410`). So Bandit is blind to the lxml parse.
  The inversion is the point: the parser Bandit flags (stdlib) is the one modern
  Python already hardened against the file read; **lxml**, the one that still
  performs the XXE, is invisible.
- **Semgrep community** (156 rules) and the full **registry** (`r/python`, 371
  rules) → **0** on the lxml view. The registry's `use-defused-xml-parse` rule
  fires on neither the lxml nor a stdlib `fromstring` probe.
- **The custom rule** ([`rules/xxe.yaml`](../../rules/xxe.yaml)) flags an lxml parse
  that doesn't go through `defusedxml` — the `resolve_entities=True` footgun and a
  bare implicit-defaults parse — and is silent on the `defusedxml` fix and a
  hardened `parser=` object. Its limits (name-based; source-agnostic) are `todook`/
  documented in `rules/xxe.py`.

XXE is also a **DAST** class — the `curl` file-read above is the dynamic probe (an
OWASP ZAP XXE scan would do the same, and add an out-of-band callback for blind
XXE). No automated DAST transcript is committed; `tests.py` plus the `curl` demo
are the deterministic proof.

Bandit and Semgrep are pinned but **not bundled in the lab image**. Install them on
the host — `pip install bandit==1.9.4 semgrep==1.170.0` — and run them there; SAST
reads the source directly. All commands run from the repository root.
