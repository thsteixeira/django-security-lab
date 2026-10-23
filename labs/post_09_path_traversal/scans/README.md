# Captured scan evidence — Lab 09 (Path Traversal)

These are the **real, unedited scanner runs** behind the post's detection
section. Each file starts with a header giving the exact command, tool version,
and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | — | **0 findings on both views** — Bandit's one path-traversal check, `B202`, is for `tarfile` |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 | SAST | ✅ custom rule asserted (hermetic job) | curated packs miss it; the registry rule misses the *realistic* form (raw probes in section C); the repo's custom taint rule catches it |

## The standard tools miss this class — and the reason is instructive

Path traversal via `os.path.join()` is a textbook bug, so the intuition is that
the standard tools must catch it. They do not — and *why* is the teaching point.

### Bandit — 0/0, structural

Bandit's ~42 plugins are dangerous-**call**/construct checks matched on the AST
(shell, `eval`, `yaml.load`, `mark_safe`, `ssl`…). Its one path-traversal check,
`B202` (CWE-22), covers `tarfile.extractall`, not a path built from a request,
and Bandit does no taint/dataflow to connect `request.GET` → `os.path.join` →
`open`. So Bandit is silent on both the vulnerable and the secure view — no
signal at all.

### Semgrep community — no curated pack includes the rule

A Django path-traversal rule **does exist** in the Semgrep registry:
`python.django.security.injection.path-traversal.path-traversal-join` (metadata
`subcategory: audit`, `confidence: LOW`). But **none of the curated community
packs includes it.** Empirically: `p/django` +
`p/python` + `p/owasp-top-ten` (156 rules) report **0 even on the one-liner the
rule matches directly**, and the whole `r/python` registry (371 rules) is 0 on the
realistic vulnerable view. Lab 02 (`avoid-mark-safe`) and Lab 08 (`csrf-exempt`)
show the same gap.

### The registry rule, run directly, misses the *realistic* form

This is the real finding. The rule is a **`pattern-either` of fixed shapes**
(not taint). Its only two-hop shape is
`$V = request.$W.get($X)` … `$P = os.path.join(..., $V, ...)` … `open($P, ...)`,
and `get($X)` matches a **one-argument** call only. Reproduced with one-function
probes (the 2026-10-23 rows are raw runs in `semgrep.txt` section C):

| Code shape | `path-traversal-join` |
|---|---|
| `open(os.path.join(base, request.GET.get('f')))` — inlined | **1 finding** |
| `name = request…` → `open(os.path.join(base, name))` — 1 hop | **1 finding** |
| `path = os.path.join(base, request…)` → `open(path)` — 1 hop | **1 finding** |
| `name = request.GET.get('f')` → `path = os.path.join(base, name)` → `open(path)` — 2 hops, one-argument read (2026-10-23) | **1 finding** |
| `name = request.GET.get('f', '')` → `path = …` → `open(path)` — 2 hops, read with a default (2026-10-23) | **0 findings** |
| a 3-hop chain (`raw = request…` → `name = raw.strip()` → `path` → `open`) (2026-10-23) | **0 findings** |
| the blog post's original Pattern 1, verbatim (Aug 11) | **0 findings** |

The two-hop chain with a default is the **post's own Pattern 1** and how real
download views are written (assign the filename with a default, build the path,
`open` the path — often with an `os.path.exists` check or logging in between).
The inlined one-liner the rule *does* catch is written rarely, not never. This
README used to put the miss down to the OSS engine following only one variable
indirection, with Semgrep Pro's taint as the only bridge; **that was wrong**: the
rule fires on the two-hop chain when the read has one argument, and the free OSS
engine's intraprocedural taint follows the chain, as the custom rule below shows.
So an off-the-shelf rule exists that gives **false confidence**: it lights up on
a toy inline and stays dark on the realistic code.

Because the shipped rule does **not** fire on the realistic vulnerable view,
§6.4.1's "don't duplicate a rule Semgrep ships" exception (the Lab 08 case) does
not apply. A custom rule that catches the multi-variable form is genuinely
additive.

## The custom rule — [`rules/path_traversal.yaml`](../../../rules/path_traversal.yaml)

The repo's **fifth custom rule**: a **taint rule**, which the free OSS engine runs
within a function. Sources are anything read from `request` and the parameters
after `request` in a view's signature (URL kwargs); the sinks are `open()`'s path
and a path whose `.open()`, `.read_bytes()` or `.read_text()` is called; the
sanitizers are `safe_join()`, a record lookup (`get_object_or_404`,
`Model.objects…`) and an `if not p.is_relative_to(base):` check on a
`p = (…).resolve()` that raises or returns (an unresolved path still fires:
`is_relative_to()` is lexical). Taint flows through `os.path.join`, pathlib's `/` and plain
assignments, so it fires on the vulnerable view's multi-variable form (and on
longer chains, `pathlib` reads, URL kwargs) and is silent on the `safe_join`
fix, the record lookup, the symlink-aware check and a hardcoded join.

```bash
semgrep scan --config rules/path_traversal.yaml labs/post_09_path_traversal/views_vulnerable.py  # 1 finding
semgrep scan --config rules/path_traversal.yaml labs/post_09_path_traversal/views_secure.py      # 0 findings
```

**Known limits** (documented in `rules/path_traversal.py` and the rule): a name
the view validates itself in any other shape (a regex allowlist) still fires,
because Semgrep cannot read the check — a false positive marked `todook`; and
the OSS engine's taint does not cross functions or files, so a name read in one
function and opened in another is missed. (The earlier syntactic version of this
rule had the opposite false positive: it fired on a join of hardcoded literals.)

## DAST

Path traversal is a runtime class, so it is DAST-detectable — OWASP ZAP's
path-traversal active-scan rule (or a Burp/`ffuf` `../`-fuzz) would fire `../`
payloads at the `?file=` parameter and confirm out-of-root file contents in the
response. The lab README's `curl` walkthrough **is** that dynamic probe,
reproducible from a clone: `GET ?file=../flag.txt` and the flag comes back. No
separate automated-scanner transcript is committed — ZAP is a heavy daemon against
the command-line-first convention, and the deterministic `tests.py` plus the
`curl` demo cover the same ground. Like all DAST here, it would not run in CI.

## Reproducing the probes

The one-function probes in the table above are trivial to recreate: put each
snippet in its own `.py` file and run
`semgrep scan --config r/python.django.security.injection.path-traversal.path-traversal-join <file>`.
The four 2026-10-23 probes and their raw output are in `semgrep.txt` section C.
The boundary is the read, not the hop count: a one-argument `.get()` or a
subscript matches the two-hop shape, a `.get()` with a default does not.
