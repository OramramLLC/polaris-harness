"""SLA threshold and ticket ID normalization helpers."""

from __future__ import annotations

from triage_engine.models import Severity

SLA_HOURS: dict[Severity, int] = {
    "P1": 1,
    "P2": 4,
    "P3": 24,
    "P4": 72,
}

SEVERITY_RANK: dict[Severity, int] = {
    "P1": 1,
    "P2": 2,
    "P3": 3,
    "P4": 4,
}


def normalize_ticket_id(ticket_id: str) -> str:
    """Normalize ticket identifiers for canonical deduplication."""
    # BUG: fails to fold case, so 'inc-101' and 'INC-101' do not deduplicate.
    return ticket_id.strip()


def is_sla_breached(severity: Severity, age_hours: float) -> bool:
    """Return True when a ticket has reached or exceeded its severity SLA threshold."""
    # BUG: strict '>' misses exact boundary breaches (e.g., age_hours == 1.0 for P1).
    return age_hours > SLA_HOURS[severity]


def highest_severity(first: Severity, second: Severity) -> Severity:
    """Return the higher-priority (lower rank) severity."""
    return first if SEVERITY_RANK[first] <= SEVERITY_RANK[second] else second
