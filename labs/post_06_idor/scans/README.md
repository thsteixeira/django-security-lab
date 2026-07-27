# Captured scan evidence — Lab 06 (IDOR / Broken Access Control)

These are the **real, unedited scanner runs** behind the post's detection
section, committed so you can read exactly what each tool reported without
booting the lab or installing anything. Each file starts with a header giving
the exact command, tool version, and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | ⚠️ scanned, not asserted | **0 findings on the views** — misses the IDOR; only `B106` noise on the test password |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 (`p/django`, `p/python`, `p/owasp-top-ten`) | SAST | ⚠️ scanned, not asserted | **0 findings** on both views — 156 community rules, none for owner-unscoped lookups |
| [`semgrep-custom-rule.txt`](semgrep-custom-rule.txt) | Semgrep 1.170.0 (`rules/idor.yaml`) | SAST | ✅ asserted (hermetic job) | the custom rule fires on the vulnerable view (line 23) and is **silent** on the secure one |

## The standard tools MISS this class — so we wrote a rule

Lab 01 (SQL injection) asserts in CI that the SAST tools **fire on the
vulnerable view and stay silent on the secure one**. Here neither standard tool
fires on the bug at all — and for a deeper reason than a missing plugin: IDOR is
a *semantic authorization* flaw, not a dangerous call.

**Bandit reports nothing on the views** — and *something* useless. Bandit matches
risky constructs node-by-node on the AST; it ships **42 plugin tests, all of them
dangerous-call/construct checks** (`subprocess ... shell=True`, `eval`,
`mark_safe`, `yaml.load`, weak SSL, and so on). **None models authorization**, so
`get_object_or_404(Note, pk=pk)` — a perfectly ordinary ORM call — matches
nothing. The only thing Bandit flags in the whole module is a `B106`
hardcoded-password on the *test fixture* (`password="labpass"` in `tests.py`):
noise unrelated to the class, and a test literal rather than a real secret. A
clean report on genuinely vulnerable views is a **miss**, not a pass — and
triaging that lone false alarm to nothing is itself the analyst's job.

**Semgrep's community rules report nothing either** (0/0, 156 Python rules). The
packs an analyst actually runs (`p/django`, `p/python`, `p/owasp-top-ten`) ship
**no rule for owner-unscoped object lookups**. Semgrep's own documentation says
exactly why, and it is worth quoting because it doubles as the justification for
writing our own rule:

> "Unlike traditional injection attacks, IDOR isn't about where the input goes.
> IDOR is closer to a logic flaw: it's the absence of an authorization check at
> the right point in the request flow." … "What is required, is writing custom
> rules for your application that describe the access control logic you're
> expecting."
> — [Semgrep, *IDOR Detection with Semgrep*](https://docs.semgrep.dev/learn/vulnerabilities/idor)

The vulnerable and the fixed view differ only by an application-specific
predicate (`owner=request.user`); a generic rule cannot know that a `Note` *has*
an owner that *should* match the requester. That is the §6.4.1 case — the
standard tools **miss a genuinely Django-specific pattern** — so a **custom
rule** earns its place: [`rules/idor.yaml`](../../../rules/idor.yaml), with the
stem-paired fixture [`rules/idor.py`](../../../rules/idor.py).

```bash
# the standard tools — miss the class (Bandit finds only a test-password false alarm)
bandit -r labs/post_06_idor/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_06_idor/views_vulnerable.py

# the custom rule — catches it
semgrep --test --config rules/ rules/
semgrep scan --config rules/idor.yaml labs/post_06_idor/views_vulnerable.py   # 1 finding (line 23)
semgrep scan --config rules/idor.yaml labs/post_06_idor/views_secure.py       # 0 findings
```

The rule is deliberately **syntactic**: it flags `get_object_or_404` /
`get_list_or_404` calls that carry no `owner=`/`user=` scoping kwarg, and goes
silent once one is present — so it fires on the vulnerable view and not on the
owner-scoped fix. Taint mode does not help here: there is no dangerous data flow
to trace, only a *missing predicate*. Its two honest limits are documented in the
fixture: a lookup scoped by an app-specific field name it doesn't know
(`account=request.user`) is a false positive (`# todook`), and a raw
`Model.objects.get(pk=...)` — the same bug outside the shortcut — slips past it
(`# todoruleid`).

## Why no DAST here

IDOR is a runtime, URL-driven class, so black-box tools *can* reach it — but they
share the same blind spot the SAST tools have, for the same reason. A scanner
firing `/idor/vulnerable/1/`, `/2/`, `/3/` sees three `200 OK` responses and no
error; it has **no way to know that note 2 belongs to Bob and should have been
off-limits to Alice**. Confirming IDOR automatically requires teaching the tool
the ownership model — which authenticated user *should* be able to read which
object — i.e. exactly the application-specific access-control logic Semgrep's docs
describe. OWASP ZAP's access-control testing can *assist* (drive two
authenticated sessions and diff what each may reach), but the authorization
intent still has to be supplied by a human. So there is no push-button DAST
capture for this lab; the automatable signal is the custom rule above.
