"""Interface stubs for live LLM and external CLI coding-agent adapters (Phase 2)."""

from __future__ import annotations

from dataclasses import dataclass

from polaris_harness.agents.base import AgentContext, AgentRunResult


@dataclass(frozen=True)
class GeminiAgentConfig:
    """Configuration for a Gemini API tool-calling agent adapter."""

    model: str = "gemini-2.5-pro"
    max_turns: int = 20
    temperature: float = 0.0


class GeminiAgentAdapter:
    """Stub adapter for Gemini API tool-use loops over `AirlockSession`."""

    name = "gemini-live"

    def __init__(self, config: GeminiAgentConfig | None = None) -> None:
        self.config = config or GeminiAgentConfig()

    def run(self, ctx: AgentContext) -> AgentRunResult:
        raise NotImplementedError(
            "Live model execution is disabled in v0.1 offline core; configure API/CLI backend in Phase 2."
        )


@dataclass(frozen=True)
class CliAgentConfig:
    """Configuration for driving an external coding-agent CLI over an Airlock MCP config."""

    executable: str
    extra_args: tuple[str, ...] = ()


class CliSubprocessAgentAdapter:
    """Stub adapter for external CLI coding agents (e.g., Gemini CLI, Claude Code, Codex)."""

    name = "cli-live"

    def __init__(self, config: CliAgentConfig) -> None:
        self.config = config

    def run(self, ctx: AgentContext) -> AgentRunResult:
        raise NotImplementedError(
            "Live model execution is disabled in v0.1 offline core; configure API/CLI backend in Phase 2."
        )


__all__ = [
    "CliAgentConfig",
    "CliSubprocessAgentAdapter",
    "GeminiAgentAdapter",
    "GeminiAgentConfig",
]
