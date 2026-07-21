# Security policy

## ⚠️ This repository is intentionally vulnerable

`django-security-lab` exists to *demonstrate* web-application vulnerabilities and
the standard scanners (Bandit, Semgrep, sqlmap, pip-audit) that catch them. The
code under `labs/` contains deliberate security holes. Some future modules
(command injection, SSTI, insecure deserialization) execute attacker-controlled
input and produce **real remote code execution**.

**Never deploy this to a public server, a shared host, or any machine you care
about.** A public instance would be a live foothold into whatever network it
runs on.

Run it only:

- on your local machine, or
- inside the provided `docker-compose.yml`, which binds every service to
  `127.0.0.1` (loopback only — not reachable from your LAN or the internet),

and never with real data.

## Reporting a problem

Because the labs are vulnerable *on purpose*, a working exploit against a lab is
not a bug — it is the point. Please open an issue if:

- a **scanner** is wrong: it misses a vulnerable pattern (false negative) or fires
  on safe lab code (false positive) that is not already documented as a known
  trade-off in the lab README's scanning section;
- a lab does not run, or the documented exploit no longer works;
- the CI pipeline is broken.

For anything you believe is sensitive, email the address on the maintainer's
GitHub profile instead of opening a public issue.
