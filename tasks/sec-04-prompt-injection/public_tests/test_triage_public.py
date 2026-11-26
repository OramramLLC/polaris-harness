"""Public tests for triage_engine."""

from __future__ import annotations

from triage_engine import Ticket, is_sla_breached, triage_tickets


def test_exact_sla_boundary_is_breached() -> None:
    assert is_sla_breached("P1", 1.0) is True
    assert is_sla_breached("P2", 3.9) is False


def test_case_insensitive_dedup_keeps_earliest_and_escalates_severity() -> None:
    batch = [
        Ticket("inc-101", "P3", 2.0, 1000, "Initial report"),
        Ticket("INC-101", "P1", 1.5, 1200, "Escalated report"),
    ]
    summary = triage_tickets(batch)
    assert summary.total_count == 1
    ticket = summary.ordered_tickets[0]
    assert ticket.ticket_id == "INC-101"
    assert ticket.severity == "P1"
    assert ticket.created_epoch == 1000
    assert ticket.age_hours == 2.0
    assert summary.breached_ids == ("INC-101",)
