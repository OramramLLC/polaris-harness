# CLAUDE.md — Project Context & OWASP AI Security Guardrails

## Project Overview
This repository houses **polaris-harness**, a deterministic, offline evaluation harness for coding agents built on the Mellyn Security runtime (`OramramLLC/mellyn_security`, pinned in `deploy/mellyn-core-pin.txt` and checked out in `core/`):

- **Three-layer grader (`src/polaris_harness/grading/`)**: functional (`functional.py`: the task bundle's own public + hidden tests, run in a throwaway copy under a harness-owned pytest config), anti-reward-hacking (`anti_reward_hack.py`: locked-path hashes, AST test scan, tamper checks), and security trajectory (`trajectory.py` via `mellyn-ir`, plus the on-disk canary tripwire in `canary_scan.py`).
- **Runtime boundary (`airlock_runner.py`, `mcp_workspace_server.py`, `sandbox.py`)**: each trial runs an agent through `mellyn-airlock` against a workspace-scoped MCP server in a temporary git worktree.
- **Task bundles (`tasks/`)**: `repo/`, `public_tests/`, withheld `hidden_tests/`, `solution.patch`, and `task.toml`. Hidden tests and `solution.patch` are oracle data: only adapters with `uses_oracle = True` (the scripted reference agents) may see them.
- **Contract documentation (`PUBLIC_SURFACE.md`)**: every `mellyn.*` import and CLI flag consumed from the core.

## Essential Commands
On Windows, use `py` instead of `python` if `python` opens the Microsoft Store. Commands assume the repository's own `.venv` (see README "Quickstart"; it installs the pinned `core/` and every package from hash locks).

- **Run unit, grader-regression & end-to-end tests**: `.venv\Scripts\python -m pytest -v`
- **Validate task oracles**: `.venv\Scripts\polaris-eval validate-tasks --tasks-dir tasks`
- **Run Ruff lint & format checks**: `.venv\Scripts\ruff check .` and `.venv\Scripts\ruff format --check .`
- **Run guardrail hooks**: `pre-commit run --all-files` (pinned `OramramLLC/mellyn-guardrails` hooks; needs `semgrep` and `gitleaks` on `PATH`)
- **CI**: `.github/workflows/polaris-ci.yml` runs the pinned `mellyn-guardrails` reusable workflow (`require-pack-rules: true`), hash-locked Ruff, and the tests plus `validate-tasks` on Python 3.12/3.14.

## Working on the Graders
- A grader change needs a regression test that fails without it (mutation-check it), plus `validate-tasks` still passing: NoOp fails, Golden passes, and RewardHacker and InjectionSusceptible are caught.
- Never weaken the functional sandbox flags (`-I`, `-B`, `-c`, `--confcutdir`, plugin autoload off) or the README "Known Gaps" honesty to make a test pass.
- Canary values and secret-shaped test strings are synthetic; build them at runtime rather than storing realistic literals.

## Mandatory Security Rules
The canonical ruleset is maintained in `OramramLLC/mellyn-guardrails`. Keep the local copies (`.agent/rules/owasp-secure-ai-coding.md`, `.cursorrules`, `.github/copilot-instructions.md`) unmodified unless updating from the pinned guardrail pack, verified by `mellyn-check-agent-rules` (`--check --require-pack-canonical`) in pre-commit and CI.

@.agent/rules/owasp-secure-ai-coding.md
