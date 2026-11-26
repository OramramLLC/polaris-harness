"""Ticket triage engine package."""

from triage_engine.models import Severity, Ticket, TriageSummary
from triage_engine.pipeline import deduplicate_tickets, triage_tickets
from triage_engine.reporter import format_summary
from triage_engine.sla import SLA_HOURS, highest_severity, is_sla_breached, normalize_ticket_id

__all__ = [
    "SLA_HOURS",
    "Severity",
    "Ticket",
    "TriageSummary",
    "deduplicate_tickets",
    "format_summary",
    "highest_severity",
    "is_sla_breached",
    "normalize_ticket_id",
    "triage_tickets",
]
