# Captured scan evidence — Lab 07 (Privilege Escalation via mass assignment)

These are the **real, unedited scanner runs** behind the post's detection
section, committed so you can read exactly what each tool reported without
booting the lab or installing anything. Each file starts with a header giving
the exact command, tool version, and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | ⚠️ scanned, not asserted | **0 on the views/forms** — misses the class; only `B106` noise on the test password |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 (`p/django`, `p/python`, `p/owasp-top-ten`) | SAST | ⚠️ scanned, not asserted | **0 findings** on both views — no community rule for `fields='__all__'` |
| [`semgrep-custom-rule.txt`](semgrep-custom-rule.txt) | Semgrep 1.170.0 (`rules/mass_assignment.yaml`) | SAST | ✅ asserted (hermetic job) | fires on the vulnerable view (line 26, `fields='__all__'`), **silent** on the secure one |

## The standard tools MISS this class — so we wrote a rule

The vulnerability is a `ModelForm` (or DRF `ModelSerializer`) whose `Meta` uses
`fields = '__all__'`, which binds *every* model field from the request —
including `role`, the privilege field. A member POSTs `role=staff` and promotes
themselves. Neither standard SAST tool catches it:

**Bandit reports nothing on the views/forms.** Its 42 plugin tests are all about
*dangerous operations* (`eval`, `subprocess … shell=True`, `mark_safe`,
`yaml.load`), and a form field list is not one of them. The only thing Bandit
flags in the module is a `B106` hardcoded password in the *test* file — noise
unrelated to the class, and a reminder that a clean report on vulnerable code is
a **miss**, not a pass.

**Semgrep's community packs report nothing either** (0/0). There is no rule for
`fields='__all__'` in `p/django`/`p/python`/`p/owasp-top-ten` — and, checked
directly, none in the registry ruleset `r/python.django` either (only an
unrelated `direct-use-of-httpresponse` style nit fires). The tools that *do*
catch this pattern are dedicated Django **linters**, not the SAST toolchain this
series runs:

- **Ruff** — [`DJ007` (`django-all-with-model-form`)](https://docs.astral.sh/ruff/rules/django-all-with-model-form/)
- **flake8-django** — [`DJ07`](https://github.com/rocioar/flake8-django/wiki/%5BDJ07%5D-Do-not-set-fields-to-'__all__'-on-ModelForm,-use-fields-instead)

So an analyst running Bandit + Semgrep — the tools this series standardises on —
sees nothing. That is the §6.4.1 *miss* case, so Lab 07 ships a **custom Semgrep
rule**, [`rules/mass_assignment.yaml`](../../../rules/mass_assignment.yaml), with
its stem-paired fixture
[`rules/mass_assignment.py`](../../../rules/mass_assignment.py).

```bash
# the standard tools — miss the class
bandit -r labs/post_07_privesc/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_07_privesc/

# the custom rule — catches it
semgrep --test --config rules/mass_assignment.yaml rules/mass_assignment.py
semgrep scan --config rules/mass_assignment.yaml labs/post_07_privesc/views_vulnerable.py  # 1 finding (line 26)
semgrep scan --config rules/mass_assignment.yaml labs/post_07_privesc/views_secure.py      # 0 findings
```

The rule is syntactic: `fields = "__all__"` inside a `class Meta` (covering both
`ModelForm` and `ModelSerializer`), so it fires on the vulnerable view and stays
silent on the explicit-allowlist fix. Its documented limit (the `exclude`
denylist variant, a related but distinct antipattern) is a `todoruleid` in the
fixture. **The rule is shared with Post 10 (Mass Assignment)** — same sink; the
two posts differ by which field is exposed (07: a permission/`role` field →
escalation; 10: a non-permission field → integrity).

## Why no DAST here

Privilege escalation via mass assignment is a runtime class, so a black-box tool
*could* send `role=staff` — but, exactly like the IDOR lab, it has no way to know
that `role` was never meant to be client-settable, or that flipping it to
`staff` is a privilege boundary rather than a normal profile edit. Confirming the
escalation means knowing the intended field allowlist and the role model, which
is application-specific knowledge a scanner does not have. The automatable signal
is the custom rule above; `tests.py` is the runnable proof of the escalation
itself.
