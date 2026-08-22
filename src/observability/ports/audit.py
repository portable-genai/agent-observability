"""Audit-sink port — the WORM persistence concern expressed as an interface.

Three interchangeable adapter families implement this Protocol:

* ``adapters/gcp/cloud_logging_audit``  — writes to a *locked* Cloud Logging bucket
  (Write-Once-Read-Many, rule R2). Read-back queries the Cloud Logging API.
* ``adapters/local/audit``              — an append-only SQLite WORM stand-in (no Google
  Cloud SDK), so the service runs locally and tests pass offline. Seedable and
  deterministic; optional Firestore-emulator branch for higher fidelity.
* ``adapters/onprem/audit``             — the fail-fast Google Distributed Cloud migration
  placeholder: satisfies the Protocol, every method raises ``NotImplementedError``.

``record`` MUST be append-only: an implementation may never expose update/delete.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import AuditEvent


@runtime_checkable
class AuditSinkPort(Protocol):
    def record(self, event: AuditEvent) -> None:
        """Append one already-redacted ``AuditEvent`` to immutable WORM storage."""
        ...

    def record_once(
        self,
        event: AuditEvent,
        *,
        idempotency_key: str,
        payload_digest: str,
    ) -> str:
        """Persist one event idempotently and return its stable event ID."""
        ...

    def get(self, event_id: str) -> AuditEvent | None:
        """Resolve one immutable audit event by its stable ID."""
        ...

    def read_recent(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        limit: int = 50,
    ) -> list[AuditEvent]:
        """Return recent events (newest first), optionally filtered, for read-back demos."""
        ...
