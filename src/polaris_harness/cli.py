"""CLI entrypoint (`polaris-eval`) for task validation, evaluation runs, and scorecard generation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Literal, cast

from polaris_harness.agents import (
    AgentAdapter,
    GoldenAgent,
    InjectionSusceptibleAgent,
    NoOpAgent,
    RewardHackerAgent,
)
from polaris_harness.reporting import load_run_report, render_scorecard_markdown
from polaris_harness.runner import run_evaluation, validate_tasks

_AGENT_FACTORIES: dict[str, type[AgentAdapter]] = {
    "golden": GoldenAgent,
    "noop": NoOpAgent,
    "reward-hacker": RewardHackerAgent,
    "injection-susceptible": InjectionSusceptibleAgent,
}


def _resolve_agents(names: list[str] | None) -> list[AgentAdapter]:
    selected = names if names else ["golden", "noop", "reward-hacker", "injection-susceptible"]
    adapters: list[AgentAdapter] = []
    for name in selected:
        factory = _AGENT_FACTORIES.get(name)
        if factory is None:
            raise ValueError(f"Unknown agent {name!r}; expected one of {', '.join(_AGENT_FACTORIES)}")
        adapters.append(factory())
    return adapters


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="polaris-eval",
        description="Polaris coding-agent evaluation harness with Mellyn Airlock telemetry.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_val = sub.add_parser("validate-tasks", help="Verify all tasks satisfy base-fail, golden-pass, and trap checks.")
    p_val.add_argument("--tasks-dir", type=Path, default=Path("tasks"), help="Root directory of task bundles.")
    p_val.add_argument("--mode", choices=("observe", "enforce"), default="observe", help="Mellyn Airlock mode.")
    p_val.add_argument("--output-dir", type=Path, default=None, help="Optional directory to write report artifacts.")

    p_run = sub.add_parser("run", help="Run evaluation trials across tasks and agents.")
    p_run.add_argument("--tasks-dir", type=Path, default=Path("tasks"), help="Root directory of task bundles.")
    p_run.add_argument("--task", action="append", dest="tasks", default=None, help="Filter to specific task_id(s).")
    p_run.add_argument(
        "--agent",
        action="append",
        dest="agents",
        choices=tuple(_AGENT_FACTORIES),
        default=None,
        help="Agent(s) to evaluate (default: all scripted agents).",
    )
    p_run.add_argument("--k", type=int, default=1, help="Number of trials per (task, agent) pair.")
    p_run.add_argument("--mode", choices=("observe", "enforce"), default="observe", help="Mellyn Airlock mode.")
    p_run.add_argument("--output-dir", type=Path, default=None, help="Directory for run_report.json & scorecard.md.")

    p_rep = sub.add_parser("report", help="Render a Markdown scorecard from an existing run_report.json.")
    p_rep.add_argument("report_json", type=Path, help="Path to run_report.json.")
    p_rep.add_argument("--output", type=Path, default=None, help="Optional output path for scorecard.md.")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `polaris-eval`."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "validate-tasks":
        mode = cast(Literal["observe", "enforce"], args.mode)
        ok, checks, report = validate_tasks(args.tasks_dir, airlock_mode=mode, output_dir=args.output_dir)
        sys.stdout.write("=== Polaris Task Oracle Validation ===\n")
        for line in checks:
            sys.stdout.write(line + "\n")
        sys.stdout.write(
            f"\nResult: {'ALL ORACLE CHECKS PASSED' if ok else 'ORACLE VALIDATION FAILED'} "
            f"({len(report.results)} trials executed)\n"
        )
        return 0 if ok else 1

    if args.command == "run":
        mode = cast(Literal["observe", "enforce"], args.mode)
        agents = _resolve_agents(args.agents)
        report = run_evaluation(
            args.tasks_dir,
            agents,
            task_ids=args.tasks,
            k_trials=args.k,
            airlock_mode=mode,
            output_dir=args.output_dir,
        )
        sys.stdout.write(render_scorecard_markdown(report))
        return 0

    if args.command == "report":
        report = load_run_report(args.report_json)
        md = render_scorecard_markdown(report)
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(md, encoding="utf-8", newline="\n")
        else:
            sys.stdout.write(md)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
