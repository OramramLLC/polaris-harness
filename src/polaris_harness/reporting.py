"""Metrics (`pass@k`, `pass^k`), JSON report serialization, and Markdown scorecards."""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from polaris_harness.schemas import GradingResult, RunReport, TaskSummary


def compute_pass_at_k(n: int, c: int, k: int) -> float:
    """Unbiased estimator `pass@k = 1 - C(n - c, k) / C(n, k)` (probability >=1 of k trials pass)."""
    if n < 1 or k < 1 or k > n:
        raise ValueError(f"Invalid parameters for pass@k: n={n}, c={c}, k={k}")
    if c < 0 or c > n:
        raise ValueError(f"Invalid pass count c={c} for n={n}")
    if n - c < k:
        return 1.0
    return 1.0 - (math.comb(n - c, k) / math.comb(n, k))


def compute_pass_pow_k(n: int, c: int, k: int) -> float:
    """Consistency estimator `pass^k = C(c, k) / C(n, k)` (probability all k sampled trials pass)."""
    if n < 1 or k < 1 or k > n:
        raise ValueError(f"Invalid parameters for pass^k: n={n}, c={c}, k={k}")
    if c < 0 or c > n:
        raise ValueError(f"Invalid pass count c={c} for n={n}")
    if c < k:
        return 0.0
    return math.comb(c, k) / math.comb(n, k)


def summarize_results(results: Sequence[GradingResult], k_trials: int) -> tuple[TaskSummary, ...]:
    """Aggregate trial results per `(task_id, agent_name)` into `TaskSummary` rows."""
    grouped: dict[tuple[str, str], list[GradingResult]] = defaultdict(list)
    for res in results:
        grouped[(res.task_id, res.agent_name)].append(res)

    summaries: list[TaskSummary] = []
    for (task_id, agent_name), items in sorted(grouped.items()):
        n = len(items)
        c = sum(1 for item in items if item.composite_passed)
        func_rate = sum(1 for item in items if item.functional_passed) / n
        anti_rate = sum(1 for item in items if item.anti_hack.passed) / n
        sec_rate = sum(1 for item in items if item.trajectory.passed) / n
        comp_rate = c / n

        ks = sorted({1, min(k_trials, n), n})
        pass_at_k = {f"pass@{k}": round(compute_pass_at_k(n, c, k), 4) for k in ks}
        pass_pow_k = {f"pass^{k}": round(compute_pass_pow_k(n, c, k), 4) for k in ks}
        mean_calls = round(sum(len(item.tool_calls) for item in items) / n, 2)

        summaries.append(
            TaskSummary(
                task_id=task_id,
                agent_name=agent_name,
                trials=n,
                composite_passes=c,
                functional_pass_rate=round(func_rate, 4),
                anti_hack_pass_rate=round(anti_rate, 4),
                security_pass_rate=round(sec_rate, 4),
                composite_pass_rate=round(comp_rate, 4),
                pass_at_k=pass_at_k,
                pass_pow_k=pass_pow_k,
                mean_tool_calls=mean_calls,
                verdicts=tuple(item.verdict for item in items),
            )
        )
    return tuple(summaries)


def render_scorecard_markdown(report: RunReport) -> str:
    """Format a `RunReport` into a portfolio-ready Markdown scorecard."""
    lines: list[str] = [
        f"# Polaris Evaluation Scorecard (`{report.run_id}`)",
        "",
        f"- **Created (UTC):** `{report.created_utc}`",
        f"- **Airlock Mode:** `{report.airlock_mode}`",
        f"- **Trials per (task, agent):** `{report.k_trials}`",
        f"- **Total Trials:** `{len(report.results)}`",
        "",
        "## Summary Matrix",
        "",
        "| Task | Agent | Trials | Composite | Functional | Anti-Hack | Security "
        "| pass@1 | pass^k | Avg Tools | Verdicts |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    max_k_key = f"pass^{report.k_trials}"
    for s in report.summaries:
        p1 = s.pass_at_k.get("pass@1", s.composite_pass_rate)
        pk = s.pass_pow_k.get(max_k_key, s.composite_pass_rate)
        verdict_str = ", ".join(s.verdicts)
        lines.append(
            f"| `{s.task_id}` | `{s.agent_name}` | {s.trials} | "
            f"{s.composite_pass_rate:.0%} ({s.composite_passes}/{s.trials}) | "
            f"{s.functional_pass_rate:.0%} | {s.anti_hack_pass_rate:.0%} | {s.security_pass_rate:.0%} | "
            f"{p1:.2f} | {pk:.2f} | {s.mean_tool_calls:.1f} | `{verdict_str}` |"
        )

    lines.extend(
        [
            "",
            "## Trial Telemetry Details",
            "",
            "| Task | Agent | Trial | Verdict | Public | Hidden | Anti-Hack | IR Status | Blocks (Enf/Obs) |",
            "| --- | --- | ---: | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for r in report.results:
        pub = f"{r.public_tests.passed_count}P/{r.public_tests.failed_count}F"
        hid = f"{r.hidden_tests.passed_count}P/{r.hidden_tests.failed_count}F"
        ah = "PASS" if r.anti_hack.passed else "FAIL"
        blocks = f"{r.trajectory.enforced_block_count}/{r.trajectory.observed_block_count}"
        lines.append(
            f"| `{r.task_id}` | `{r.agent_name}` | {r.trial_index} | `{r.verdict}` | "
            f"{pub} | {hid} | {ah} | `{r.trajectory.ir_status}` | {blocks} |"
        )

    lines.extend(
        [
            "",
            "## What This Evaluates & Limitations",
            "",
            "- **Evaluated:** Functional correctness against withheld hidden tests, locked-path SHA-256 integrity, "
            "Python AST test-weakening detection, and `mellyn-airlock` / `mellyn-ir` hash-chained trajectory "
            "compliance.",
            "- **Limitations (v0.1):** Runs in local temporary `git worktree` sandboxes rather than rootless "
            "containers (`DockerSandbox` is stubbed for Phase 2), so code executed by `run_tests` and the graders is "
            "not contained and the on-disk canary scan is only a tripwire; verifies deterministic scripted agents "
            "offline; live LLM/CLI adapters are interface stubs pending API credentials.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_run_report(report: RunReport, output_dir: Path) -> tuple[Path, Path]:
    """Write `run_report.json` and `scorecard.md` under `output_dir`."""
    out = output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "run_report.json"
    md_path = out / "scorecard.md"
    json_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8", newline="\n")
    md_path.write_text(render_scorecard_markdown(report), encoding="utf-8", newline="\n")
    return json_path, md_path


def load_run_report(report_path: Path) -> RunReport:
    """Load and strictly validate a `RunReport` JSON file."""
    return RunReport.model_validate_json(report_path.read_text(encoding="utf-8"))


__all__ = [
    "compute_pass_at_k",
    "compute_pass_pow_k",
    "load_run_report",
    "render_scorecard_markdown",
    "summarize_results",
    "write_run_report",
]
