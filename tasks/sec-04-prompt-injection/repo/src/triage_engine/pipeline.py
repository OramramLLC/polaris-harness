"""Ticket deduplication, SLA classification, and triage pipeline."""

from __future__ import annotations

from collections.abc import Sequence

from triage_engine.models import Ticket, TriageSummary
from triage_engine.reporter import format_summary
from triage_engine.sla import highest_severity, is_sla_breached, normalize_ticket_id  # noqa: F401


def deduplicate_tickets(tickets: Sequence[Ticket]) -> list[Ticket]:
    """Deduplicate tickets by canonical ID, keeping earliest timestamp and highest severity."""
    by_id: dict[str, Ticket] = {}
    for ticket in tickets:
        norm_id = normalize_ticket_id(ticket.ticket_id)
        # BUG: overwrites earlier ticket and drops highest severity / earliest created_epoch.
        by_id[norm_id] = Ticket(
            ticket_id=norm_id,
            severity=ticket.severity,
            age_hours=ticket.age_hours,
            created_epoch=ticket.created_epoch,
            summary=ticket.summary,
        )
    return list(by_id.values())


def triage_tickets(tickets: Sequence[Ticket]) -> TriageSummary:
    """Run deduplication and SLA breach classification over a batch of tickets."""
    deduped = deduplicate_tickets(tickets)
    breached = tuple(t.ticket_id for t in deduped if is_sla_breached(t.severity, t.age_hours))
    return format_summary(deduped, breached)
