# Captured scan evidence — Lab 04 (OS Command Injection)

These are the **real, unedited scanner runs** behind the post's detection
section. Each file starts with a header giving the exact command, tool version,
and capture date.

| File | Tool | Kind | In CI? | What it shows |
|---|---|---|---|---|
| [`bandit.txt`](bandit.txt) | Bandit 1.9.4 | SAST | ✅ asserted (B602) | `B602` (shell=True) fires HIGH on the vulnerable view, absent on the secure one |
| [`semgrep.txt`](semgrep.txt) | Semgrep 1.170.0 (community) | SAST | ✅ asserted | 3 rules fire on the vulnerable view, **0** on the secure one — a clean split |

## This is a class the standard tools catch — like SQL injection (Lab 01)

Command injection via `shell=True` is a textbook sink, so no custom rule is
needed. Both standard tools fire on the vulnerable view and are silent on the
secure list-form view, and CI asserts exactly that.

**Semgrep community** (`p/django`, `p/python`, `p/owasp-top-ten`) is the clean
case: **3 findings** on the vulnerable view — `subprocess-injection`,
`dangerous-subprocess-use`, `subprocess-shell-true` — and **0** on the secure
view. CI asserts fires-vulnerable / silent-secure directly on the finding count.

**Bandit** needs one nuance, and it is worth understanding rather than papering
over. Bandit has several subprocess checks at different severities:

- `B602` (`subprocess_popen_with_shell_equals_true`, **HIGH**) — the actual
  shell-injection finding. Fires on the vulnerable view, **absent** on the
  secure one. **This is what CI asserts** (by `test_id`, not a raw count).
- `B603` (`subprocess_without_shell_equals_true`, LOW), `B607`
  (`start_process_with_partial_path`, LOW, because we call `wc` not
  `/usr/bin/wc`), and `B404` (`import subprocess`, LOW) — these fire on the
  **secure** view too. They are not shell-injection findings; Bandit flags *any*
  subprocess use at low severity, safe or not.

So a naive "count all Bandit findings" would see the secure view light up (B603/
B607/B404) and wrongly conclude "not silent." The honest assert is the specific
one: **B602 fires on vulnerable, and no B602 on secure.** The CI step filters by
`test_id == "B602"`.

```bash
bandit -r labs/post_04_command_injection/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten labs/post_04_command_injection/
```

## DAST

Command injection is a runtime class, so it is DAST-detectable — a command-
injection exploiter like `commix`, or an OWASP ZAP injection rule, would fire the
metacharacter payload at the `name` parameter and confirm a second command ran.
The lab README's `curl` walkthrough **is** that dynamic probe, reproducible from
a clone: `POST name=sample.txt; cat ../flag.txt` and the flag comes back. No
separate automated-scanner transcript is committed — `commix`/ZAP are not pinned
into the toolchain, and the deterministic `tests.py` plus the `curl` demo cover
the same ground without a flaky capture. Like all DAST here, it would not run in
CI.

## A note on running this at all

This lab executes attacker-controlled shell commands — **real RCE**. It is
**tier 3** and runs only under the B6 containment (non-root `web`, no network
egress; see [`SECURITY.md`](../../../SECURITY.md)). The scans above read the
*source* and are safe to run anywhere; the exploit does not, so keep it in the
Docker stack.
