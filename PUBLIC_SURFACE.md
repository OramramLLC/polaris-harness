# Mellyn Security Public Surface Consumed by `polaris-harness`

All dependencies on `mellyn-security` (`OramramLLC/mellyn_security`, pinned to the commit in `deploy/mellyn-core-pin.txt` and checked out in `core/`) are isolated behind **two boundary modules** so offline tests, audits, and future version pins have a single narrow interface.

## 1. Runtime Interception Boundary (`src/polaris_harness/airlock_runner.py`)

### Python Imports
- `mellyn.airlock.engine`:
  - `compute_manifest_pin(tools: Sequence[ToolDefinition]) -> str`
  - `compute_tool_pin(tool: ToolDefinition) -> str`
- `mellyn.airlock.models`:
  - `ToolDefinition`
  - `parse_airlock_policy_toml(toml_text: str) -> AirlockPolicy`

### Subprocess CLI Invocation
Spawned via `sys.executable -m mellyn.airlock.proxy` with flags:
- `--policy <path/to/airlock_policy.toml>`
- `--audit-log <path/to/audit.jsonl>`
- `--session-id <session_id>`
- `--mode observe|enforce`
- `--timeout <seconds>`
- `--record-redacted-payloads` (when enabled)
- `--allow-env PYTHONPATH`
- `-- <sys.executable> -m polaris_harness.mcp_workspace_server --root <workspace_path>`

## 2. Trajectory Grading Boundary (`src/polaris_harness/grading/trajectory.py`)

### Python Imports
- `mellyn.ir_lab.reconstruct`:
  - `reconstruct_incident(path: Path) -> IncidentReport`

### Consumed `IncidentReport` Fields
- `chain_valid: bool`
- `status: Literal["CLEAN", "BLOCKED_ACTIVITY", "OBSERVED_VIOLATIONS", "AAD_CONTAINED", "AAD_TRIGGERED_UNCONFIRMED", "INTEGRITY_COMPROMISED"]`
- `verification.reason: str`
- `total_events: int`
- `observed_block_count: int`
- `observed_aad_count: int`
- `terminal_event` (`containment_confirmed: bool | None`)
- `sessions[*].block_precursors` and `sessions[*].events[*]` (`severity`, `rule_id`)

## 3. Packaging & Fail-Closed Contract
- `mellyn-security` is **not** declared in `pyproject.toml` `[project.dependencies]`. It is installed editable from the pinned `core/` checkout, matching `mellyn-redteam` supply-chain rules.
- If `mellyn.airlock` or `mellyn.ir_lab` cannot be imported, `airlock_runner.py` and `trajectory.py` fail closed by raising the shared `polaris_harness.errors.MellynUnavailableError`.
