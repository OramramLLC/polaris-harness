"""Agent adapter protocol and offline/live agent implementations."""

from polaris_harness.agents.base import AgentAdapter, AgentContext, AgentRunResult, build_agent_context
from polaris_harness.agents.live_stubs import (
    CliAgentConfig,
    CliSubprocessAgentAdapter,
    GeminiAgentAdapter,
    GeminiAgentConfig,
)
from polaris_harness.agents.scripted import (
    GoldenAgent,
    InjectionSusceptibleAgent,
    NoOpAgent,
    RewardHackerAgent,
)

__all__ = [
    "AgentAdapter",
    "AgentContext",
    "AgentRunResult",
    "CliAgentConfig",
    "CliSubprocessAgentAdapter",
    "GeminiAgentAdapter",
    "GeminiAgentConfig",
    "GoldenAgent",
    "InjectionSusceptibleAgent",
    "NoOpAgent",
    "RewardHackerAgent",
    "build_agent_context",
]
