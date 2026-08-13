# Captured scan evidence — Lab 10 (Mass Assignment via DRF `ModelSerializer`)

These are the **real, unedited scanner runs** behind the post's detection
section, committed so you can read exactly what each tool reported without
booting the lab or installing anything. Each file starts with a header giving
the exact command, tool version, and capture date (2026-08-13).

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | ⚠️ scanned, not asserted | **0 on the views/serializers** — misses the class; only `B106` noise on the test password |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 (`p/django`, `p/python`, `p/owasp-top-ten`; + registry `r/python.django`, `r/python`) | SAST | ⚠️ scanned, not asserted | **0 findings** on the serializer — no community *or* registry rule for `fields='__all__'` |
| [`semgrep-custom-rule.txt`](semgrep-custom-rule.txt) | Semgrep 1.170.0 (`rules/mass_assignment.yaml`) | SAST | ✅ asserted (hermetic job) | fires on the vulnerable view (line 25, `fields='__all__'`), **silent** on the secure one |

## The standard tools MISS this class — the same rule as Lab 07 catches it

The vulnerability is a DRF `ModelSerializer` whose `Meta` uses
`fields = '__all__'`, which makes *every* column on `Order` writable from the
request — `price`, `paid`, `status`, `owner`. A customer PATCHes
`{"price": "0.00", "paid": true}` and the order is now free and paid. Neither
standard SAST tool catches it.

**Bandit reports nothing on the views/serializers.** Its 42 plugin tests are all
about *dangerous operations* (`eval`, `subprocess … shell=True`, `mark_safe`,
`yaml.load`); a serializer field list is not one of them. The only thing Bandit
flags in the module is a `B106` hardcoded password in the *test* file — noise
unrelated to the class, and a reminder that a clean report on vulnerable code is
a **miss**, not a pass.

**Semgrep's community packs report nothing either** — and this is the point
worth flagging, because **the post's own draft detection guidance claimed
`semgrep --config p/django` flags `fields='__all__'` on serializers.** Checked
directly, it does not: `p/django`/`p/python`/`p/owasp-top-ten` are **0** on the
`ModelSerializer(fields='__all__')` view, and the registry tier (`r/python.django`,
`r/python`) — run before concluding "miss," per the detection procedure — is **0**
too. (This is the same inaccuracy corrected for Post 7, whose draft made the
identical claim.) The tools that *do* catch this pattern are dedicated Django
**linters**, not the SAST toolchain this series runs:

- **Ruff** — [`DJ007` (`django-all-with-model-form`)](https://docs.astral.sh/ruff/rules/django-all-with-model-form/)
- **flake8-django** — [`DJ07`](https://github.com/rocioar/flake8-django/wiki/%5BDJ07%5D-Do-not-set-fields-to-'__all__'-on-ModelForm,-use-fields-instead)

Note that Ruff's `DJ007` is scoped to `ModelForm`; on the DRF `ModelSerializer`
side even the linter coverage thins out, which is why a **custom Semgrep rule**
earns its place here.

## The custom rule is shared with Lab 07

[`rules/mass_assignment.yaml`](../../../rules/mass_assignment.yaml) is **one rule
serving two labs.** It keys on `fields = "__all__"` inside a `class Meta`, which
is framework-agnostic — so it fires on Lab 07's Django `ModelForm` *and* on this
lab's DRF `ModelSerializer` with no change. The two labs differ not in the sink
but in the **field and the impact**:

- **Lab 07** over-posts `role` → a *permission* field → privilege escalation (A01).
- **Lab 10** over-posts `price`/`paid`/`owner` → *ordinary business* fields →
  a data-integrity failure on a legally/financially meaningful record (A08).

Both are asserted in the hermetic custom-rules CI job (fires on the vulnerable
view, silent on the secure one), against the same rule file.

**Known limit** (documented in `rules/mass_assignment.py`): the rule targets
`fields = "__all__"` specifically. The `exclude = [...]` denylist variant — a
related but distinct antipattern that fails *open* as the model grows — is not
caught (a `# todoruleid` in the fixture).

## DAST

Mass assignment is also an automatable **dynamic** class: the `curl` PATCH in the
lab README (over-post fields the form never rendered, then read the record back)
is the probe, and an API scanner can replay it. But it detects the *effect*, and
a scanner cannot know that `price`/`paid` are not client-settable or that the
forged state crosses a business boundary — the same semantic caveat as the IDOR
lab. No automated DAST transcript is committed; `tests.py` plus the `curl` demo
are the deterministic proof.

Bandit and Semgrep are pinned but **not bundled in the lab image**. Install them
on the host — `pip install bandit==1.9.4 semgrep==1.170.0` — and run them there;
SAST reads the source directly. All commands run from the repository root.
