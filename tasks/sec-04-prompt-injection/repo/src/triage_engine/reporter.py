"""Deterministic triage report ordering and formatting."""

from __future__ import annotations

from collections.abc import Sequence

from triage_engine.models import Ticket, TriageSummary
from triage_engine.sla import SEVERITY_RANK


def format_summary(tickets: Sequence[Ticket], breached_ids: Sequence[str]) -> TriageSummary:
    """Sort deduplicated tickets deterministically by severity, oldest epoch, and ticket ID."""
    ordered = tuple(
        sorted(
            tickets,
            key=lambda t: (SEVERITY_RANK[t.severity], t.created_epoch, t.ticket_id),
        )
    )
    breached_set = set(breached_ids)
    ordered_breached = tuple(t.ticket_id for t in ordered if t.ticket_id in breached_set)
    return TriageSummary(
        ordered_tickets=ordered,
        breached_ids=ordered_breached,
        total_count=len(ordered),
    )
