"""Domain models for agent-observability.

These dataclasses are the in-process contract the ports speak. Their field names mirror
the compliance-advisory domain (``AuditEvent`` / ``Citation`` / ``Decision`` in
``compliance_advisory.domain.models``) so the JSON that crosses the wire (see
:mod:`observability.schemas`) is identical on both ends. Enums serialise to ``.value``.

Important: ``redacted_prompt`` / ``redacted_response`` arrive **already de-identified**
by the upstream A1 guardrail/DLP redaction (rule R1, P-04). This service never redacts;
it only serialises, stores immutably (WORM, rule R2), and reads back. No raw PII should
ever reach this code path.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime


def utcnow() -> datetime:
    """Timezone-aware UTC now (matches the compliance-advisory domain helper)."""
    return datetime.now(tz=UTC)


class Decision(enum.Enum):
    """Outcome of one assistant interaction (mirrors compliance-advisory ``Decision``)."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    ESCALATED = "escalated"  # routed to a human (maker-checker)


@dataclass(frozen=True, slots=True)
class Citation:
    """Regulator-grade provenance attached to a generated claim (mirrors compliance-advisory
    ``Citation``).

    agent-observability stores citations verbatim; it does not interpret ``regulator`` /
    ``jurisdiction``
    as enums (they cross the wire as plain strings) so it stays decoupled from compliance-advisory's
    enum surface and accepts any catalog system's events.
    """

    source_id: str
    regulator: str
    jurisdiction: str
    title: str
    url: str
    version: str = "unknown"
    page: int | None = None
    snippet: str = ""
    score: float | None = None


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """An immutable, WORM-stored Audit Event v2 (rule R2).

    The content fields are deliberately named ``redacted_*`` for every producer,
    including control-plane services whose content is operational rather than customer
    text. Correlation fields are vendor-neutral W3C identifiers and remain optional for
    legacy producers.
    """

    action: str  # "ask" | "checklist" | "testcases" | "regulator_questions"
    actor: str  # authenticated user / service identity
    decision: Decision
    redacted_prompt: str
    redacted_response: str
    citations: tuple[Citation, ...] = ()
    resource: str = "compliance-advisory"
    trace_id: str | None = None
    span_id: str | None = None
    correlation_id: str | None = None
    run_id: str | None = None
    event_id: str = ""
    schema_version: str = "audit-event/v2"
    timestamp: datetime = field(default_factory=utcnow)
    metadata: dict[str, str] = field(default_factory=dict)
