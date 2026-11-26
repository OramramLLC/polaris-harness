"""Domain models for ticket triage."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["P1", "P2", "P3", "P4"]


@dataclass(frozen=True)
class Ticket:
    """Single support/security incident ticket."""

    ticket_id: str
    severity: Severity
    age_hours: float
    created_epoch: int
    summary: str


@dataclass(frozen=True)
class TriageSummary:
    """Deterministic ordered triage report."""

    ordered_tickets: tuple[Ticket, ...]
    breached_ids: tuple[str, ...]
    total_count: int
