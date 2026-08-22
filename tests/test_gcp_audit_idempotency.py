from __future__ import annotations

from dataclasses import replace

import pytest

from helpers import sample_event
from observability.adapters.gcp.cloud_logging_audit import CloudLoggingAuditAdapter
from observability.errors import IdempotencyConflict
from observability.schemas import AuditEventModel


class _Snapshot:
    def __init__(self, body: dict[str, str] | None) -> None:
        self._body = body
        self.exists = body is not None

    def to_dict(self) -> dict[str, str] | None:
        return self._body


class _Document:
    def __init__(self, store: dict[str, dict[str, str]], key: str) -> None:
        self._store = store
        self._key = key

    def create(self, body: dict[str, str]) -> None:
        if self._key in self._store:
            raise RuntimeError("already exists")
        self._store[self._key] = body

    def get(self) -> _Snapshot:
        return _Snapshot(self._store.get(self._key))


class _Collection:
    def __init__(self, store: dict[str, dict[str, str]]) -> None:
        self._store = store

    def document(self, key: str) -> _Document:
        return _Document(self._store, key)


class _Firestore:
    def __init__(self) -> None:
        self.docs: dict[str, dict[str, str]] = {}

    def collection(self, name: str) -> _Collection:
        assert name == "audit_idempotency"
        return _Collection(self.docs)


class _Logger:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def log_struct(self, payload, **kwargs) -> None:
        self.calls.append({"payload": payload, **kwargs})


def test_gcp_sink_rejects_duplicate_event_id_across_idempotency_keys(settings) -> None:
    adapter = CloudLoggingAuditAdapter(settings)
    firestore = _Firestore()
    logger = _Logger()
    adapter._firestore_client = firestore
    adapter._logger = logger
    event = AuditEventModel.model_validate(sample_event(event_id="audit-fixed")).to_domain()

    assert (
        adapter.record_once(event, idempotency_key="request-one", payload_digest="sha256:one")
        == "audit-fixed"
    )
    with pytest.raises(IdempotencyConflict):
        adapter.record_once(
            replace(event, redacted_response="different"),
            idempotency_key="request-two",
            payload_digest="sha256:two",
        )
    assert len(logger.calls) == 1
