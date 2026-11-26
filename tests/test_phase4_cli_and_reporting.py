"""Phase 4 exit-gate tests: pass@k/pass^k math, runner, reporting, and CLI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from polaris_harness.cli import main as cli_main
from polaris_harness.reporting import (
    compute_pass_at_k,
    compute_pass_pow_k,
    load_run_report,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
TASKS_ROOT = REPO_ROOT / "tasks"


def test_pass_at_k_and_pass_pow_k_math() -> None:
    assert compute_pass_at_k(5, 0, 1) == 0.0
    assert compute_pass_at_k(5, 0, 3) == 0.0
    assert compute_pass_at_k(5, 5, 1) == 1.0
    assert compute_pass_at_k(5, 3, 3) == 1.0
    assert pytest.approx(compute_pass_at_k(4, 2, 2), rel=1e-6) == 1.0 - (1 / 6)

    assert compute_pass_pow_k(5, 0, 1) == 0.0
    assert compute_pass_pow_k(5, 2, 3) == 0.0
    assert compute_pass_pow_k(5, 5, 5) == 1.0
    assert pytest.approx(compute_pass_pow_k(4, 2, 2), rel=1e-6) == (1 / 6)

    with pytest.raises(ValueError):
        compute_pass_at_k(3, 1, 4)
    with pytest.raises(ValueError):
        compute_pass_pow_k(3, 4, 1)


def test_cli_validate_tasks_end_to_end(tmp_path: Path) -> None:
    out_dir = tmp_path / "validate-out"
    rc = cli_main(
        [
            "validate-tasks",
            "--tasks-dir",
            str(TASKS_ROOT),
            "--mode",
            "observe",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert rc == 0
    report = load_run_report(out_dir / "run_report.json")
    assert len(report.results) == 7
    assert (out_dir / "scorecard.md").is_file()


def test_cli_run_k2_and_report_command(tmp_path: Path) -> None:
    out_dir = tmp_path / "run-out"
    rc = cli_main(
        [
            "run",
            "--tasks-dir",
            str(TASKS_ROOT),
            "--task",
            "swe-03-path-traversal",
            "--agent",
            "golden",
            "--agent",
            "noop",
            "--k",
            "2",
            "--mode",
            "observe",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert rc == 0

    report_json = out_dir / "run_report.json"
    loaded = load_run_report(report_json)
    assert loaded.k_trials == 2
    assert len(loaded.results) == 4
    by_agent = {s.agent_name: s for s in loaded.summaries}
    assert by_agent["golden"].composite_pass_rate == 1.0
    assert by_agent["golden"].pass_at_k["pass@2"] == 1.0
    assert by_agent["golden"].pass_pow_k["pass^2"] == 1.0
    assert by_agent["noop"].composite_pass_rate == 0.0

    # Test `polaris-eval report` subprocess entrypoint
    custom_md = tmp_path / "custom_scorecard.md"
    proc = subprocess.run(  # noqa: S603 - fixed local python -m invocation
        [sys.executable, "-m", "polaris_harness.cli", "report", str(report_json), "--output", str(custom_md)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    md_text = custom_md.read_text(encoding="utf-8")
    assert "Polaris Evaluation Scorecard" in md_text
    assert "`swe-03-path-traversal`" in md_text
