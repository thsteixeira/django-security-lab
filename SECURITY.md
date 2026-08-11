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

## Safety tiers and containment

Not every lab carries the same blast radius, so containment is matched to it
rather than being uniform:

- **Tier 1–2** (most labs) — the vulnerability reads confined data, writes lab
  state, or reads a confined filesystem / render context. The baseline posture
  (loopback-only, never deployed, idempotent seed) is the containment.
- **Tier 3** — the vulnerability yields **arbitrary code or command execution**:
  **Lab 04 (OS command injection)** and **Lab 27 (insecure deserialization)**
  (and Lab 03 / SSTI *only* if a Jinja2 branch is ever added). These run under
  extra containment defined in `docker-compose.yml` and the `Dockerfile`:
  - the `web` container runs as a **non-root user** (`labuser`), so an exploit
    that reaches a shell is not root inside the container, and `/app` is
    read-only to it;
  - the `web` container has **no outbound network** — it sits on an `internal`
    Docker network with no route off the host, so an RCE cannot phone home,
    exfiltrate data, or pull a second-stage payload. A tiny `socat` gateway
    (which runs no lab code) publishes the lab to `127.0.0.1:8000`.

Even so: **run tier-3 labs only inside the provided Docker stack, on a machine
you control, and never with real data.** The containment shrinks the blast
radius; it is not a licence to run this anywhere but locally.

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
