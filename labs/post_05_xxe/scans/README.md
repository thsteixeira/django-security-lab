# Captured scan evidence — Lab 05 (XXE)

These are the **real scanner runs** behind the post's detection section:
`bandit.txt` holds the full Bandit run, and `semgrep.txt` keeps each Semgrep
run's result lines. Each file starts with a header giving the exact command,
tool version, and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | — | **0/0** — Bandit flags the *stdlib* parsers, but its lxml check (B410) was removed |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 | SAST | ✅ custom rule asserted (hermetic job) | community + registry miss the lxml XXE; the repo's custom rule catches it |

## The standard tools miss lxml XXE — and *which* parser they miss is the point

Path-traversal-style intuition says a textbook class like XXE must be caught. It
is — but only on the parser you no longer need to worry about.

### Bandit — flags the stdlib, blind to lxml

Bandit's XML plugins are **name-based**: `B405`/`B314` fire on `xml.etree`
(and `.fromstring`), `B313`–`B319` and `B406`–`B409` on `sax`/`expatbuilder`/
`minidom`/`pulldom`, each recommending `defusedxml`. Confirmed: a stdlib `ET.fromstring(b)` lights up `B405` + `B314`.

But the lab's vulnerable view parses with **lxml**, and Bandit's lxml checks —
**`B320`** (calls) and **`B410`** (import) — have been **removed**. Ask for it explicitly and Bandit 1.9.4 answers
`Unknown test found in profile: B410`. So Bandit has no rule that matches an lxml
parse and reports **0 on both views**.

The inversion is the teaching point: modern **stdlib** ElementTree no longer
resolves external entities, so the parser Bandit *does* flag is the one already
hardened against the file read — while **lxml**, the parser that still performs
the XXE (with `resolve_entities=True`, or lxml's defaults before 5.0), is the one
Bandit is blind to. A green Bandit run on XML-parsing code says less than it looks.

*(Bandit's own tracker records that the lxml guidance was unhelpful — the
`defusedxml.lxml` shim it pointed to was only ever an example and is deprecated:
[PyCQA/bandit#767](https://github.com/PyCQA/bandit/issues/767),
[#716](https://github.com/PyCQA/bandit/issues/716).)*

### Semgrep — community and registry both 0 on lxml

`p/django` + `p/python` + `p/owasp-top-ten` (156 rules) report **0** on both
views, and the full `r/python` registry (371 rules) is **0** on the vulnerable
view. The registry *does* carry an XXE rule
(`python.lang.security.use-defused-xml-parse`), but run directly it fires on
**neither** the lxml view nor a stdlib `ET.fromstring` probe — it targets a
different (`.parse`-style) sink. No shipped rule gives a fire/silent assert on the
lxml XXE.

## The custom rule — [`rules/xxe.yaml`](../../../rules/xxe.yaml)

The repo's **sixth custom rule**. It flags an lxml parse that does not go through
`defusedxml`: the explicit `etree.XMLParser(resolve_entities=True)` footgun, and a
bare `etree.fromstring/parse/XML` that passes no parser, positionally or as
`parser=`, and so relies on lxml's version-dependent defaults.
It stays silent on the `defusedxml.ElementTree` fix and on a hardened lxml parser
passed via `parser=` (the post's Pattern 3 fix).

```bash
semgrep scan --config rules/xxe.yaml labs/post_05_xxe/views_vulnerable.py  # 1 finding
semgrep scan --config rules/xxe.yaml labs/post_05_xxe/views_secure.py      # 0 findings
```

**Known limits** (documented in `rules/xxe.py`): the rule is **name-based** (keys
on an `etree` receiver, so `import defusedxml.ElementTree as etree` would be a
false positive) and **source-agnostic** (it can't prove the bytes are untrusted).
It trusts **any** `parser=` object, hardened or not, and it is silent (checked with
Semgrep 1.170.0) on `etree.iterparse(...)` and `etree.ETCompatXMLParser()` — the two
entry points that resolved external entities by default until lxml 6.1.0
(CVE-2026-41066) — on `lxml.etree.fromstring(...)` written out in full, and on
`fromstring` / `XMLParser` imported from `lxml.etree`.
Confirming reachability from a request body is taint analysis the OSS engine won't
do here.

## DAST

XXE is a runtime class — an OWASP ZAP XXE active-scan rule, or a Burp payload,
would POST a `file://` external-entity document and confirm out-of-band file
contents (or an out-of-band callback for blind XXE). The lab README's `curl`
walkthrough **is** that dynamic probe, reproducible from a clone: POST the
external-entity XML and the flag comes back. No automated-scanner transcript is
committed — ZAP is a heavy daemon against the command-line-first convention, and
the deterministic `tests.py` plus the `curl` demo cover the same ground. Like all
DAST here, it would not run in CI.

## A note on containment

The `file://` read is confined to files the non-root `web` user can read. The
`http://169.254.169.254/` SSRF-to-metadata escalation the post describes does
not happen here: the vulnerable parser keeps lxml's `no_network=True` default,
which blocks URL fetches although `resolve_entities=True` is set. B6 (`web` has
no network egress) is the second wall. The file-read variant is the one this lab demonstrates.
