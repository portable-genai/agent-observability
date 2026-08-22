"""Cloud Logging WORM audit adapter — regulator-grade immutable audit trail (rule R2).

Backs :class:`~observability.ports.audit.AuditSinkPort` with **Cloud Logging**. Each
:class:`~observability.models.AuditEvent` is written as a structured log entry to
``settings.logging.log_name``. A Cloud Logging **sink** (provisioned in
``infra/terraform/logging_worm.tf``) routes that log into a **locked log bucket** —
Write-Once-Read-Many, retention ``settings.logging.retention_days`` (~7 years) — so
records are immutable: this is the Hrz5 WORM guarantee that Rsk1 depends on (rule R2, P-08).

Read-back (``GET /v1/audit``) queries the same log via the Cloud Logging API, newest
first, bounded to a recent window — strictly for demos / regulator pulls, not bulk
export (that is the BigQuery FinOps path; see the README).

Important: ``redacted_prompt`` / ``redacted_response`` arrive **already de-identified**
upstream (rule R1, P-04). This adapter never redacts; it only serialises and writes.

The Cloud Logging SDK import is **lazy** so the on-prem and test profiles import this
module without the SDK present.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from ...config import Settings
from ...errors import IdempotencyConflict
from ...models import AuditEvent, Citation, Decision

# Severity by decision: blocked / escalated interactions are surfaced for compliance
# review at a higher log level than ordinary allowed answers.
_SEVERITY_BY_DECISION: dict[Decision, str] = {
    Decision.ALLOWED: "INFO",
    Decision.ESCALATED: "WARNING",
    Decision.BLOCKED: "WARNING",
}


class CloudLoggingAuditAdapter:
    """Write/read already-redacted ``AuditEvent`` records to/from the locked WORM bucket."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._log_name = settings.logging.log_name
        self._window = timedelta(days=settings.logging.read_back_window_days)
        self._client: Any | None = None
        self._logger: Any | None = None
        self._firestore_client: Any | None = None

    # ------------------------------------------------------------------ #
    # Lazy SDK plumbing
    # ------------------------------------------------------------------ #
    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        from google.cloud import logging_v2  # lazy: Cloud Logging SDK only on gcp

        # verify: https://cloud.google.com/logging/docs/reference/libraries
        self._client = logging_v2.Client(project=self._settings.project_id)
        return self._client

    def _get_logger(self) -> Any:
        if self._logger is not None:
            return self._logger
        self._logger = self._get_client().logger(self._log_name)
        return self._logger

    # ------------------------------------------------------------------ #
    # AuditSinkPort.record
    # ------------------------------------------------------------------ #
    def record(self, event: AuditEvent) -> None:
        """Serialise and write one immutable audit record (routed to WORM by the sink)."""
        from ...serialization import to_jsonable

        event_id = event.event_id.strip() or f"audit-{uuid4().hex}"
        normalized = replace(event, event_id=event_id)
        encoded = json.dumps(to_jsonable(normalized), sort_keys=True, separators=(",", ":"))
        digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        self.record_once(
            normalized,
            idempotency_key=f"event:{event_id}",
            payload_digest=digest,
        )

    def record_once(
        self,
        event: AuditEvent,
        *,
        idempotency_key: str,
        payload_digest: str,
    ) -> str:
        """Reserve retry and event identities, then write with Cloud Logging insertId."""
        from ...serialization import to_jsonable

        event_id = event.event_id.strip()
        key = idempotency_key.strip()
        digest = payload_digest.strip()
        if not event_id or not key or not digest:
            raise ValueError("event_id, idempotency_key, and payload_digest are required")
        # Reserve both caller retry identity and immutable event identity. Cloud
        # Logging's insertId deduplicates delivery, while these two records make a
        # conflicting event-id reuse observable before the WORM write.
        self._reserve_idempotency_key(f"idempotency:{key}", event_id, digest)
        self._reserve_idempotency_key(f"event:{event_id}", event_id, digest)
        logger = self._get_logger()
        payload = to_jsonable(event)
        severity = _SEVERITY_BY_DECISION.get(event.decision, "INFO")
        # Structured labels keep the WORM bucket queryable for demos / regulator pulls
        # without parsing the JSON payload; they carry no free-text PII.
        labels = {
            "action": event.action,
            "actor": event.actor,
            "decision": event.decision.value,
            "resource": event.resource,
            "event_id": event_id,
            "idempotency_key_hash": hashlib.sha256(key.encode("utf-8")).hexdigest(),
            "payload_digest": digest,
        }
        if event.trace_id:
            labels["trace_id"] = event.trace_id
        # Cloud Logging deduplicates identical insert IDs. The Firestore reservation above
        # rejects conflicting key reuse across replicas before this immutable write.
        logger.log_struct(payload, severity=severity, labels=labels, insert_id=event_id)
        return event_id

    def _reserve_idempotency_key(self, key: str, event_id: str, digest: str) -> None:
        if self._firestore_client is None:
            from google.cloud import firestore  # lazy

            self._firestore_client = firestore.Client(
                project=self._settings.project_id,
                database="hrz-observability-idempotency",
            )
        doc_id = hashlib.sha256(key.encode("utf-8")).hexdigest()
        ref = self._firestore_client.collection("audit_idempotency").document(doc_id)
        try:
            ref.create(
                {
                    "event_id": event_id,
                    "payload_digest": digest,
                    "created_at": datetime.now(tz=UTC),
                }
            )
        except Exception as exc:  # Firestore's AlreadyExists type is a lazy optional import.
            existing = ref.get()
            if not getattr(existing, "exists", False):
                raise
            body = existing.to_dict() or {}
            if body.get("event_id") != event_id or body.get("payload_digest") != digest:
                raise IdempotencyConflict(
                    "idempotency key or event ID was reused for different audit content"
                ) from exc

    # ------------------------------------------------------------------ #
    # AuditSinkPort.read_recent
    # ------------------------------------------------------------------ #
    def get(self, event_id: str) -> AuditEvent | None:
        """Resolve one immutable event using its structured event-id label."""
        client = self._get_client()
        log_filter = " AND ".join(
            (
                f'logName="projects/{self._settings.project_id}/logs/{self._log_name}"',
                f'labels.event_id="{event_id}"',
            )
        )
        entries = client.list_entries(filter_=log_filter, order_by="timestamp desc", page_size=1)
        for entry in entries:
            payload = getattr(entry, "payload", None)
            if isinstance(payload, dict):
                return _event_from_payload(payload)
        return None

    def read_recent(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        limit: int = 50,
    ) -> list[AuditEvent]:
        """Read recent events via the Cloud Logging API (newest first), bounded by window."""
        client = self._get_client()
        since = (datetime.now(tz=UTC) - self._window).isoformat()
        parts = [
            f'logName="projects/{self._settings.project_id}/logs/{self._log_name}"',
            f'timestamp>="{since}"',
        ]
        if actor is not None:
            parts.append(f'labels.actor="{actor}"')
        if action is not None:
            parts.append(f'labels.action="{action}"')
        log_filter = " AND ".join(parts)

        bound = max(1, limit)
        out: list[AuditEvent] = []
        # DESCENDING => newest first; page_size caps the API round trip.
        entries = client.list_entries(
            filter_=log_filter,
            order_by="timestamp desc",
            page_size=bound,
        )
        for entry in entries:
            payload = getattr(entry, "payload", None)
            if not isinstance(payload, dict):
                continue
            out.append(_event_from_payload(payload))
            if len(out) >= bound:
                break
        return out


# --------------------------------------------------------------------------- #
# Deserialisation (read-back) — payload dict -> AuditEvent
# --------------------------------------------------------------------------- #
def _citation_from_dict(raw: dict[str, Any]) -> Citation:
    page = raw.get("page")
    score = raw.get("score")
    return Citation(
        source_id=str(raw.get("source_id", "")),
        regulator=str(raw.get("regulator", "")),
        jurisdiction=str(raw.get("jurisdiction", "")),
        title=str(raw.get("title", "")),
        url=str(raw.get("url", "")),
        version=str(raw.get("version", "unknown")),
        page=int(page) if page is not None else None,
        snippet=str(raw.get("snippet", "")),
        score=float(score) if score is not None else None,
    )


def _event_from_payload(payload: dict[str, Any]) -> AuditEvent:
    """Reconstruct an ``AuditEvent`` from a Cloud Logging structured payload."""
    decision = Decision(str(payload["decision"]))
    citations = tuple(
        _citation_from_dict(c) for c in payload.get("citations", []) if isinstance(c, dict)
    )
    ts_raw = payload.get("timestamp")
    if not isinstance(ts_raw, str):
        raise ValueError("stored audit event has no timestamp")
    timestamp = datetime.fromisoformat(ts_raw)
    metadata_raw = payload.get("metadata", {})
    metadata = (
        {str(k): str(v) for k, v in metadata_raw.items()} if isinstance(metadata_raw, dict) else {}
    )
    return AuditEvent(
        action=str(payload.get("action", "")),
        actor=str(payload.get("actor", "")),
        decision=decision,
        redacted_prompt=str(payload.get("redacted_prompt", "")),
        redacted_response=str(payload.get("redacted_response", "")),
        citations=citations,
        resource=str(payload.get("resource", "compliance-advisory")),
        trace_id=(str(payload["trace_id"]) if payload.get("trace_id") else None),
        span_id=(str(payload["span_id"]) if payload.get("span_id") else None),
        correlation_id=(str(payload["correlation_id"]) if payload.get("correlation_id") else None),
        run_id=(str(payload["run_id"]) if payload.get("run_id") else None),
        event_id=str(payload.get("event_id", "")),
        schema_version=str(payload.get("schema_version", "audit-event/v2")),
        timestamp=timestamp,
        metadata=metadata,
    )
