"""Base contracts for pluggable coding agents."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from polaris_harness.airlock_runner import AirlockSession
from polaris_harness.schemas import TaskManifest


@dataclass(frozen=True)
class AgentContext:
    """Execution context handed to an agent for a single trial.

    `oracle_task_dir` is the full task bundle, including `hidden_tests/` and `solution.patch`. The runner sets it
    only for adapters that declare `uses_oracle = True` (the scripted reference agents); every other adapter,
    including live model/CLI adapters, gets None and must work from `manifest.prompt` and the MCP tools alone.
    """

    manifest: TaskManifest
    session: AirlockSession
    oracle_task_dir: Path | None = None


@dataclass(frozen=True)
class AgentRunResult:
    """Summary returned by an agent adapter after finishing its tool trajectory."""

    agent_name: str
    notes: str = ""


@runtime_checkable
class AgentAdapter(Protocol):
    """Protocol implemented by scripted offline agents and live model/CLI adapters.

    An adapter may also set a class attribute `uses_oracle = True` to receive `AgentContext.oracle_task_dir`.
    """

    name: str

    def run(self, ctx: AgentContext) -> AgentRunResult: ...


def build_agent_context(
    agent: AgentAdapter, task_dir: Path, manifest: TaskManifest, session: AirlockSession
) -> AgentContext:
    """Build the context for `agent`, exposing the task bundle only to oracle adapters."""
    oracle_dir = task_dir if getattr(agent, "uses_oracle", False) is True else None
    return AgentContext(manifest=manifest, session=session, oracle_task_dir=oracle_dir)


__all__ = [
    "AgentAdapter",
    "AgentContext",
    "AgentRunResult",
    "build_agent_context",
]
