# Captured scan evidence — Lab 09 (Path Traversal)

These are the **real, unedited scanner runs** behind the post's detection
section. Each file starts with a header giving the exact command, tool version,
and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | — | **0 findings on both views** — Bandit has no path-traversal check |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 | SAST | ✅ custom rule asserted (hermetic job) | curated packs miss it; the registry rule misses the *realistic* form; the repo's custom rule catches it |

## The standard tools miss this class — and the reason is instructive

Path traversal via `os.path.join()` is a textbook bug, so the intuition is that
the standard tools must catch it. They do not — and *why* is the teaching point.

### Bandit — 0/0, structural

Bandit's ~42 plugins are dangerous-**call**/construct checks matched on the AST
(shell, `eval`, `yaml.load`, `mark_safe`, `ssl`…). None models path traversal,
and Bandit does no taint/dataflow to connect `request.GET` → `os.path.join` →
`open`. Its nearest plugin, `B108`, only flags a hardcoded `/tmp` path. So Bandit
is silent on both the vulnerable and the secure view — no signal at all.

### Semgrep community — the curated packs exclude the rule

A Django path-traversal rule **does exist** in the Semgrep registry:
`python.django.security.injection.path-traversal.path-traversal-join`. But it is
**excluded from the curated community packs.** Empirically: `p/django` +
`p/python` + `p/owasp-top-ten` (156 rules) report **0 even on the one-liner the
rule matches directly**, and the whole `r/python` registry (371 rules) is 0 on the
realistic vulnerable view. This is the same audit/registry-tier exclusion seen in
Lab 02 (`avoid-mark-safe`) and Lab 08 (`csrf-exempt`).

### The registry rule, run directly, misses the *realistic* form

This is the real finding. The rule is a **syntactic `pattern-either`** (not
taint), enumerating fixed shapes plus *single* variable indirections. The
community (OSS) engine follows **one** variable indirection but not two chained
ones. Reproduced with one-function probes:

| Code shape | `path-traversal-join` |
|---|---|
| `open(os.path.join(base, request.GET.get('f')))` — inlined | **1 finding** |
| `name = request…` → `open(os.path.join(base, name))` — 1 hop | **1 finding** |
| `path = os.path.join(base, request…)` → `open(path)` — 1 hop | **1 finding** |
| `name = request…` → `path = os.path.join(base, name)` → `open(path)` — **2 hops** | **0 findings** |
| the blog post's Vulnerable Pattern 1, verbatim | **0 findings** |

The two-hop chain is the **post's own Vulnerable Pattern 1** and how real download
views are written (assign the filename, build the path, `open` the path — usually
with a default, an `os.path.exists` check, or logging in between). The inlined
one-liner the rule *does* catch is written rarely, not never. Bridging both hops
is **Semgrep Pro's interprocedural/interfile taint** — absent from the community
engine. So an off-the-shelf rule exists that gives **false confidence**: it lights
up on a toy inline and stays dark on the realistic code.

Because the shipped rule does **not** fire on the realistic vulnerable view,
§6.4.1's "don't duplicate a rule Semgrep ships" exception (the Lab 08 case) does
not apply. A custom rule that catches the multi-variable form is genuinely
additive.

## The custom rule — [`rules/path_traversal.yaml`](../../../rules/path_traversal.yaml)

The repo's **fifth custom rule**. It is deliberately syntactic and keyed on the
`os.path.join` → `open` **single hop the OSS engine handles well**: an `open()`
whose path argument is — or was assigned — `os.path.join(...)`. It therefore fires
on the vulnerable view's multi-variable form and is silent on the `safe_join` fix
(which contains no `os.path.join`).

```bash
semgrep scan --config rules/path_traversal.yaml labs/post_09_path_traversal/views_vulnerable.py  # 1 finding
semgrep scan --config rules/path_traversal.yaml labs/post_09_path_traversal/views_secure.py      # 0 findings
```

**Known limit** (documented in `rules/path_traversal.py`): being syntactic and
source-agnostic, it flags an `os.path.join` fed to `open()` even when every
component is a hardcoded literal (a safe read) — a false positive marked
`todook`. Confirming the joined path is actually *user-controlled* is exactly the
taint the OSS engine cannot do, which is the whole reason the class is
under-served here.

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
The boundary is consistent — one variable indirection matches, two do not.
