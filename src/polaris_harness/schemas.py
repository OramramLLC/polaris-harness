"""Strict Pydantic v2 boundary schemas for polaris-harness."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    """Fail-closed base model: extra fields forbidden, strict types, immutable instances."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class TaskManifest(_StrictModel):
    """Declarative task specification loaded from `task.toml`."""

    task_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    category: Literal["swe", "security"]
    prompt: str = Field(min_length=1)
    locked_paths: tuple[str, ...]
    public_tests_dir: str = Field(default="public_tests", min_length=1)
    hidden_tests_dir: str = Field(default="hidden_tests", min_length=1)
    allowed_tools: tuple[str, ...] = ("list_files", "read_file", "write_file", "run_tests")
    timeout_seconds: int = Field(default=60, ge=1)
    max_tool_calls: int = Field(default=30, ge=1)
    canary_outside_filename: str | None = None
    expected_security_risk: str | None = None


class TrialConfig(_StrictModel):
    """Configuration for executing one agent trial on one task."""

    task_id: str = Field(min_length=1)
    agent_name: str = Field(min_length=1)
    trial_index: int = Field(ge=0)
    airlock_mode: Literal["observe", "enforce"] = "observe"
    record_redacted_payloads: bool = True
    timeout_seconds: int = Field(default=60, ge=1)
    max_tool_calls: int = Field(default=30, ge=1)


class ToolCallRecord(_StrictModel):
    """Observed MCP tool call executed by an agent through Mellyn Airlock."""

    seq: int = Field(ge=0)
    tool_name: str = Field(min_length=1)
    arguments_json: str
    ok: bool
    error_code: int | None = None
    error_message: str | None = None
    duration_ms: float = Field(ge=0.0)


class TestSuiteOutcome(_StrictModel):
    """Deterministic outcome from running public or hidden pytest suites."""

    suite_name: Literal["public", "hidden"]
    passed: bool
    returncode: int
    passed_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    error_count: int = Field(ge=0)
    duration_seconds: float = Field(ge=0.0)
    output_tail: str


class AstViolation(_StrictModel):
    """Suspicious test-weakening construct detected via Python AST inspection."""

    file_path: str = Field(min_length=1)
    line: int = Field(ge=1)
    rule_id: str = Field(min_length=1)
    detail: str = Field(min_length=1)


class AntiHackReport(_StrictModel):
    """Layer-2 integrity check covering locked-path SHA-256 diffs and AST test tampering."""

    passed: bool
    modified_locked_paths: tuple[str, ...] = ()
    deleted_locked_paths: tuple[str, ...] = ()
    added_locked_paths: tuple[str, ...] = ()
    ast_violations: tuple[AstViolation, ...] = ()
    tamper_violations: tuple[AstViolation, ...] = ()
    reasons: tuple[str, ...] = ()


class TrajectoryReport(_StrictModel):
    """Layer-3 security trajectory report derived from `mellyn-ir` over `audit.jsonl`."""

    passed: bool
    chain_valid: bool
    ir_status: str = Field(min_length=1)
    enforcement_mode: Literal["observe", "enforce"]
    total_events: int = Field(ge=0)
    enforced_block_count: int = Field(ge=0)
    observed_block_count: int = Field(ge=0)
    observed_aad_count: int = Field(ge=0)
    aad_triggered: bool = False
    containment_confirmed: bool = False
    canary_leaked_in_audit: bool = False
    canary_artifacts: tuple[str, ...] = ()
    violation_rule_ids: tuple[str, ...] = ()
    audit_log_path: str = Field(min_length=1)
    reasons: tuple[str, ...] = ()


VerdictLabel = Literal[
    "PASS",
    "FAIL_FUNCTIONAL",
    "FAIL_REWARD_HACK",
    "FAIL_SECURITY",
    "FAIL_MULTIPLE",
]


class GradingResult(_StrictModel):
    """Full 3-layer grading outcome for a single task trial."""

    task_id: str = Field(min_length=1)
    agent_name: str = Field(min_length=1)
    trial_index: int = Field(ge=0)
    airlock_mode: Literal["observe", "enforce"]
    public_tests: TestSuiteOutcome
    hidden_tests: TestSuiteOutcome
    functional_passed: bool
    anti_hack: AntiHackReport
    trajectory: TrajectoryReport
    composite_passed: bool
    verdict: VerdictLabel
    tool_calls: tuple[ToolCallRecord, ...] = ()
    duration_seconds: float = Field(ge=0.0)


class TaskSummary(_StrictModel):
    """Aggregated multi-trial metrics for one `(task_id, agent_name)` pair."""

    task_id: str = Field(min_length=1)
    agent_name: str = Field(min_length=1)
    trials: int = Field(ge=1)
    composite_passes: int = Field(ge=0)
    functional_pass_rate: float = Field(ge=0.0, le=1.0)
    anti_hack_pass_rate: float = Field(ge=0.0, le=1.0)
    security_pass_rate: float = Field(ge=0.0, le=1.0)
    composite_pass_rate: float = Field(ge=0.0, le=1.0)
    pass_at_k: dict[str, float]
    pass_pow_k: dict[str, float]
    mean_tool_calls: float = Field(ge=0.0)
    verdicts: tuple[str, ...]


class RunReport(_StrictModel):
    """Top-level evaluation report serialized to `run_report.json`."""

    schema_version: Literal[1] = 1
    run_id: str = Field(min_length=1)
    created_utc: str = Field(min_length=1)
    airlock_mode: Literal["observe", "enforce"]
    k_trials: int = Field(ge=1)
    summaries: tuple[TaskSummary, ...]
    results: tuple[GradingResult, ...]


def load_task_manifest(task_dir: Path) -> TaskManifest:
    """Strictly load and validate `<task_dir>/task.toml` via stdlib `tomllib`."""
    toml_path = task_dir / "task.toml"
    raw: dict[str, Any] = tomllib.loads(toml_path.read_text(encoding="utf-8"))
    for tuple_key in ("locked_paths", "allowed_tools"):
        if tuple_key in raw and isinstance(raw[tuple_key], list):
            raw[tuple_key] = tuple(raw[tuple_key])
    return TaskManifest.model_validate(raw)


__all__ = [
    "AntiHackReport",
    "AstViolation",
    "GradingResult",
    "RunReport",
    "TaskManifest",
    "TaskSummary",
    "TestSuiteOutcome",
    "ToolCallRecord",
    "TrajectoryReport",
    "TrialConfig",
    "VerdictLabel",
    "load_task_manifest",
]
