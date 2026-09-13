# Contributing

Thanks for helping improve `django-security-lab`. The repo has a strict shape so
that every lab stays provable in CI. A new module is a **runnable lab** scanned
with the standard off-the-shelf tools; a custom Semgrep rule is the rare
exception, not part of every module.

## The shape of a lab

For a topic `foo` (post number `NN`):

```
labs/post_NN_foo/views_vulnerable.py   the flagged view — CI asserts the SAST tools fire here
labs/post_NN_foo/views_secure.py       the fixed view — CI asserts the SAST tools stay silent here
labs/post_NN_foo/urls.py               /foo/vulnerable/  +  /foo/secure/
labs/post_NN_foo/models.py             public data + a separate CTF-flag table/row
labs/post_NN_foo/seed_lab.py           plants the flag + sample data (idempotent)
labs/post_NN_foo/tests.py              proves the exploit works on vulnerable, fails on secure
labs/post_NN_foo/README.md             teaching doc: exploit, fix, OWASP/CWE/ASVS, scan commands + output
```

## Workflow (lab first, scan second)

1. **Build the runnable lab** `labs/post_NN_foo/`: a vulnerable view, a secure
   view, a CTF flag revealed on successful exploit, `tests.py` that proves the
   exploit works on the vulnerable view and fails on the secure one, and a
   teaching `README.md`. `tests.py` is the universal proof — it asserts the
   exploit succeeds on the vulnerable view, is blocked on the secure one, and the
   secure view still performs its legitimate function.
2. **Scan it with the standard tools** and capture the real output for the lab
   README:
   ```bash
   bandit -r labs/post_NN_foo/                       # SAST
   semgrep scan --config p/django labs/post_NN_foo/  # SAST (community packs)
   pip-audit -r requirements.txt                     # SCA (component/CVE posts)
   sqlmap -u '.../foo/vulnerable/?param=1' --batch   # DAST (runtime classes)
   ```
   Show the exact commands, what each tool caught, and what it missed. Real
   captured output only — never hypothetical, never ad-hoc scenario files.
3. **Wire the CI assert** for classes the SAST tools catch: fire on
   `views_vulnerable.py`, silent on `views_secure.py`. DAST-only classes carry no
   SAST assert — their gate is the Django `tests.py`. DAST is captured in the
   README, not run in CI.

## The custom-rule exception

Write a custom Semgrep rule **only** when the standard scans come up empty on a
genuinely Django-specific pattern that matters — the semantic classes generic
tools don't model, e.g. `fields = '__all__'` in a `ModelForm` (mass assignment),
owner-unscoped `get_object_or_404` (IDOR), request-driven `is_staff` /
`is_superuser` assignment (privilege escalation). If Bandit or the community
packs already catch the class, do **not** write a rule — it is busywork. SQL
injection is covered, so Lab 01 ships none.

When a rule is warranted, add the pair `rules/foo.yaml` + `rules/foo.py`:

- **Write the fixture** `rules/foo.py`: annotate vulnerable lines with
  `# ruleid: <id>` and safe lines with `# ok: <id>`. Document known gaps with
  `# todoruleid:` / `# todook:` — maturity signals, not failures. `semgrep --test`
  pairs a rule to its fixture by **filename stem**, so `foo.yaml` ↔ `foo.py`.
- **Write the rule** `rules/foo.yaml` until `semgrep --test --config ./rules/ ./rules/`
  passes. Full metadata block:
  ```yaml
  metadata:
    owasp:                   # dual-listed while the ecosystem straddles both editions
      - "A01:2021 Broken Access Control"
      - "A01:2025 Broken Access Control"
    cwe: "CWE-269: ..."
    asvs: "V1.2.2"           # ties the finding to an auditable requirement
    confidence: HIGH
    references:
      - https://thiagoteixeira.tech/blog/<post-slug>/   # bidirectional link to the post
  ```
  The rule id namespace is `thiagoteixeira.django.security.<topic>.<rule>`.
- **Add an autofix (`fix:`) only where the remedy is genuinely mechanical.** If
  fixing the finding requires human judgement about what is data (as with SQL
  injection), ship without a fix and say why in the message.
- The post must say plainly *"the standard tools missed X, so I wrote a rule"* —
  that honesty is the whole justification.

## House rules

- **English only.** The repo and all its docs are English; the bilingual burden
  belongs to the blog, not here.
- **Pin tool versions** in CI. The community Semgrep packs are fetched from the
  registry (not hermetic); a custom-rule job, if present, stays hermetic
  (`--config ./rules/` only, no `--config auto` / `p/...`).
- **Settings are global; lab behaviour should not be.** A lab must not add a
  project-wide Django setting to `config/settings.py` to get its own behaviour.
  Settings apply to every lab at once, so one lab's tightening silently becomes
  every other lab's constraint — including labs that do not exist yet, whose
  authors will debug it as a mystery. Prefer, in order: (1) pass the behaviour
  explicitly at the call site (e.g. `validate_password(...,
  password_validators=...)` — most Django subsystems take an override argument
  for exactly this); (2) a per-view decorator (`@csrf_protect` in Lab 08);
  (3) `@override_settings` in `tests.py`, if only the tests need it. Add a real
  global setting **only** when the lesson *is* the global setting, and then say
  so in the lab README and in `SECURITY_LAB_MODULE_PLAN.md` so the next author
  inherits the constraint knowingly, not by surprise.

  *Worked example — Lab 13.* It first set `AUTH_PASSWORD_VALIDATORS` globally
  with a 15-character floor. That is a perfectly reasonable policy and it
  quietly invalidated the shared B7 cast password `labpass` (7 characters) and
  Lab 11's `summer2024` (10) for every future form-based lab. The policy moved
  to `labs/post_13_weak_passwords/policy.py`, passed explicitly via
  `password_validators=`. The project now carries no `AUTH_PASSWORD_VALIDATORS`
  at all — which is also more honest, since Django's real default is `[]`.

- **Postgres via `docker compose` is the one run path.** Keep `tests.py` green
  there, write CTF payloads for Postgres semantics, and capture `scans/` evidence
  against that same stack — the committed output has to match what a reader
  reproduces.
