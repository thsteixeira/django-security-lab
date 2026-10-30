# Captured scan evidence — Lab 03 (SSTI)

These are the **real, unedited scanner runs** behind the post's detection
section, committed so you can read exactly what each tool reported without
booting the lab or installing anything. Each file starts with a header giving
the exact command, tool version, and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | ⚠️ scanned, not asserted | **0 findings** on both views — no plugin models the `Template()` sink |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 (`p/django`, `p/python`, `p/owasp-top-ten`) | SAST | ⚠️ scanned, not asserted | **0 findings** on both views — 156 community rules, none for this Django sink |
| [`semgrep-custom-rule.txt`](semgrep-custom-rule.txt) | Semgrep 1.170.0 (`rules/ssti.yaml`) | SAST | ✅ asserted (hermetic job) | the custom rule fires on the vulnerable view (line 33) and is **silent** on the secure one |

## The standard tools MISS this class — so we wrote a rule

Lab 01 (SQL injection) asserts in CI that the SAST tools **fire on the
vulnerable view and stay silent on the secure one**. Here neither standard tool
fires at all — for the same underlying reason, from opposite designs:

**Bandit reports nothing** (0/0). Bandit matches risky constructs node-by-node
on the AST; it has plugins for `mark_safe` (`B308`), Jinja2 `autoescape=False`
(`B701`) and Mako (`B702`), but **no plugin treats Django's
`django.template.Template()` or `Engine.from_string()` as a sink**. A template
compiled from user input matches no rule, so it is reported as clean — a miss,
not a pass.

**Semgrep's community rules report nothing either** (0/0, 156 rules run: 151 Python, 5 multilang).
The free packs an analyst actually runs (`p/django`, `p/python`,
`p/owasp-top-ten`) centre their Django coverage on the autoescape/`mark_safe`
(XSS) side and ship **no rule for the `Template(user_input)` sink**. Semgrep
*does* carry a Flask SSTI rule (`render_template_string`), but not the Django
equivalent. And this is not just the curated packs: the **audit/registry tier**
was checked too (`semgrep --config r/python.django --config r/python`) and it
has **no** Django `Template()`/SSTI rule either — only an unrelated
`audit.xss.direct-use-of-httpresponse` style nit fires. So a custom rule is
genuinely warranted; the public community rules have nothing for this sink.

That is the §6.4.1 case: the standard tools **miss a genuinely Django-specific
pattern**, so a **custom rule** earns its place —
[`rules/ssti.yaml`](../../../rules/ssti.yaml), with the stem-paired fixture
[`rules/ssti.py`](../../../rules/ssti.py). It is deliberately syntactic: it flags
a `Template()`/`from_string()` compiled from anything that is **not** a string
literal. The secure view's source *is* a literal (`Template("{{ message }}")`),
so the rule fires on the vulnerable view and stays silent on the secure one — the
scan-assert the standard tools couldn't give. A hermetic CI job runs
`semgrep --test` on the fixture and then that fire/silent assert on the two views.

```bash
# the standard tools — miss this entirely
bandit -r labs/post_03_ssti/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_03_ssti/

# the custom rule — catches it
semgrep --test --config rules/ssti.yaml rules/ssti.py
semgrep scan --config rules/ssti.yaml labs/post_03_ssti/views_vulnerable.py   # 1 finding
semgrep scan --config rules/ssti.yaml labs/post_03_ssti/views_secure.py       # 0 findings
```

Being syntactic, the rule never traces where a non-literal came from. Semgrep's
constant propagation still clears a literal held in a variable
(`t = "{{ v }}"; Template(t)` is silent, an `ok` case in the fixture), but a
template file the project ships, read with `Path(...).read_text()`, is a false
positive, documented in the fixture as `todook` (checked with Semgrep 1.170.0 on
2026-10-23). It also matches only the call shapes it names: `Template(t, engine=e)`,
`Template(template_string=t)` and `template.Template(t)` slip past
`Template($X)` (checked with Semgrep 1.170.0 on 2026-10-22). And it cannot
tell a sandboxed Jinja2 environment from a plain one: `_sandbox.from_string(body)`,
a sandboxed call, is flagged as loudly as the bug, as is any unrelated
`.from_string()` method called on a variable.

## Why no DAST here

SSTI *does* have URL-driven DAST tools (SSTImap, tplmap, Nuclei, ZAP's SSTI
rule), unlike stored XSS — but they confirm injection through engine-specific
plugins that make the engine **evaluate** a probe such as `{{7*7}}` or raise that
engine's own errors, and Django's DTL never evaluates expressions (it raises
`TemplateSyntaxError` at parse time). SSTImap's engine list, for one, has no
Django entry. None of them has been run against this lab, so no DAST capture is
committed; none is built to notice a view leaking context. Expression-probe DAST is blind to DTL's disclosure-class SSTI;
it becomes a real, RCE-confirming capture only against an expression-evaluating
engine (a Jinja2 backend), which this lab deliberately does not ship.
