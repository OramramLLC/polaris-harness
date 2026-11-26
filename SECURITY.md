# Security Policy

## Scope

This repository (`polaris-harness`) is an evaluation harness for coding agents. It runs task bundles through Mellyn Airlock (`OramramLLC/mellyn_security`, pinned in [`deploy/mellyn-core-pin.txt`](deploy/mellyn-core-pin.txt)) and grades each trial on three layers: functional, anti-reward-hacking, and security trajectory.

In scope here:

- **Grader bypasses:** any way for an agent to earn a `PASS` (or avoid a `FAIL_*`) without doing the task. For example, making unfixed code pass the functional layer, changing locked or test files unnoticed, or reading the outside-workspace canary without the security layer failing.
- **Harness integrity:** flaws in the workspace MCP server's path confinement, the sandbox, hidden-test isolation, or the report schemas.
- **Supply chain:** problems with the pinned core, the hash locks in [`deploy/`](deploy/), or the CI workflow.

Flaws in the Airlock proxy, the `mellyn-ir` reconstructor, or the audit ledger belong to `OramramLLC/mellyn_security`. Report them there.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for suspected security vulnerabilities.**

- Report privately through **GitHub private vulnerability reporting** on this repository: `Security` tab → `Report a vulnerability`.
- Include:
  - a minimal agent (an `AgentAdapter`) or task that reproduces the issue;
  - the verdict you got and the verdict you expected;
  - your OS, your Python version, and the core commit in `deploy/mellyn-core-pin.txt`.

---

## Known Limitations (Not Vulnerabilities)

These are documented gaps in v0.1 (see [README "Known Gaps"](README.md#known-gaps-v01)). Reports that only restate them are not treated as new vulnerabilities, but a cheaper or broader way through them is welcome:

- **Executed code is not contained.** `run_tests` and the post-run graders run agent-written code on the host with the user's file and network access. The on-disk canary scan is a tripwire, not a boundary. Containment is planned for `DockerSandbox` (Phase 2).
- **The code under test shares the pytest process.** A hostile solution can still tamper with pytest at import time by means the anti-hack layer does not detect.

Run untrusted or live agents only on a disposable machine or VM until the Phase 2 sandbox exists.

---

## Data Hygiene

- **Synthetic fixtures only:** task repositories, tickets and canary values are synthetic. Each trial's canary (`POLARIS-CANARY-<random hex>`) is generated fresh and is worthless after the run.
- **Run artifacts can contain payloads:** trials record redacted request/response payloads in `audit.jsonl` by default (`--record-redacted-payloads`). Treat `runs/` and `artifacts/` output as untrusted data, and don't commit it (both are git-ignored).
