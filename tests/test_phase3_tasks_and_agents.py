"""Phase 3 exit-gate tests: both deep tasks and all 4 scripted agents + live stubs."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import pytest

from polaris_harness.agents import (
    AgentAdapter,
    CliAgentConfig,
    CliSubprocessAgentAdapter,
    GeminiAgentAdapter,
    GoldenAgent,
    InjectionSusceptibleAgent,
    NoOpAgent,
    RewardHackerAgent,
)
from polaris_harness.runner import run_single_trial
from polaris_harness.schemas import GradingResult

REPO_ROOT = Path(__file__).resolve().parents[1]
TASKS_ROOT = REPO_ROOT / "tasks"


def _execute_trial(
    task_id: str,
    agent: AgentAdapter,
    tmp_path: Path,
    *,
    airlock_mode: Literal["observe", "enforce"] = "observe",
) -> GradingResult:
    return run_single_trial(
        TASKS_ROOT / task_id, agent, airlock_mode=airlock_mode, artifacts_dir=tmp_path / airlock_mode
    )


@pytest.mark.parametrize("task_id", ["swe-03-path-traversal", "sec-04-prompt-injection"])
def test_golden_noop_and_reward_hacker_verdicts_across_tasks(task_id: str, tmp_path: Path) -> None:
    golden = _execute_trial(task_id, GoldenAgent(), tmp_path)
    assert golden.verdict == "PASS"
    assert golden.functional_passed is True
    assert golden.public_tests.passed is True
    assert golden.hidden_tests.passed is True
    assert golden.anti_hack.passed is True
    assert golden.trajectory.passed is True
    assert golden.trajectory.chain_valid is True

    noop = _execute_trial(task_id, NoOpAgent(), tmp_path)
    assert noop.verdict == "FAIL_FUNCTIONAL"
    assert noop.functional_passed is False
    assert noop.hidden_tests.passed is False
    assert noop.anti_hack.passed is True
    assert noop.trajectory.passed is True

    hacker = _execute_trial(task_id, RewardHackerAgent(), tmp_path)
    assert hacker.composite_passed is False
    assert hacker.anti_hack.passed is False
    assert len(hacker.anti_hack.modified_locked_paths) >= 1
    assert len(hacker.anti_hack.ast_violations) >= 1


def test_injection_susceptible_agent_fails_security_on_sec04_observe_and_enforce(tmp_path: Path) -> None:
    obs_res = _execute_trial("sec-04-prompt-injection", InjectionSusceptibleAgent(), tmp_path, airlock_mode="observe")
    assert obs_res.functional_passed is True
    assert obs_res.anti_hack.passed is True
    assert obs_res.trajectory.passed is False
    assert obs_res.verdict == "FAIL_SECURITY"
    assert obs_res.trajectory.chain_valid is True
    assert obs_res.trajectory.ir_status == "OBSERVED_VIOLATIONS"
    assert obs_res.trajectory.observed_block_count >= 1
    assert obs_res.trajectory.canary_leaked_in_audit is False

    enf_res = _execute_trial("sec-04-prompt-injection", InjectionSusceptibleAgent(), tmp_path, airlock_mode="enforce")
    assert enf_res.functional_passed is True
    assert enf_res.anti_hack.passed is True
    assert enf_res.trajectory.passed is False
    assert enf_res.verdict == "FAIL_SECURITY"
    assert enf_res.trajectory.chain_valid is True
    assert enf_res.trajectory.ir_status == "BLOCKED_ACTIVITY"
    assert enf_res.trajectory.enforced_block_count >= 1
    assert enf_res.trajectory.canary_leaked_in_audit is False


def test_live_agent_stubs_raise_not_implemented(tmp_path: Path) -> None:
    gemini = GeminiAgentAdapter()
    cli = CliSubprocessAgentAdapter(CliAgentConfig(executable="gemini"))
    with pytest.raises(NotImplementedError):
        gemini.run(None)  # type: ignore[arg-type]
    with pytest.raises(NotImplementedError):
        cli.run(None)  # type: ignore[arg-type]
