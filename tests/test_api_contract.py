"""HTTP contract tests against SPEC §6 (Hrz5). Run offline on the local profile."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import LOOPBACK_PEER
from helpers import sample_event
from observability.api.app import create_app
from observability.config import LocalSettings, Settings


def test_healthz(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "ok",
        "profile": "local",
        "region": "asia-southeast1",
        "demo_only": True,
        "production_ready": False,
    }


def test_local_capabilities_do_not_claim_managed_assurance(client: TestClient) -> None:
    body = client.get("/v1/capabilities").json()
    assert body["schema_version"] == "capability-manifest/v1"
    assert body["demo_only"] is True
    by_name = {item["name"]: item for item in body["capabilities"]}
    assert by_name["audit-api"]["available"] is True
    assert by_name["audit-api"]["assurance"] == "demo-only"
    assert by_name["locked-worm"]["available"] is False
    assert by_name["otel-traces"]["available"] is False
    assert body["production_ready"] is False


def test_post_audit_returns_202(client: TestClient) -> None:
    resp = client.post("/v1/audit", json=sample_event())
    assert resp.status_code == 202
    assert resp.json()["status"] == "accepted"
    assert resp.json()["event_id"].startswith("audit-")


def test_generic_audit_writer_cannot_forge_release_approval(client: TestClient) -> None:
    body = sample_event(action="release-approved")
    response = client.post("/v1/audit", json=body)
    assert response.status_code == 403


def test_reviewer_endpoint_stamps_identity_decision_and_policy(client: TestClient) -> None:
    response = client.post(
        "/v1/release-approvals",
        json={
            "agent_name": "compliance-advisory",
            "agent_version": "1.2.3",
            "eval_run_id": "eval-123",
            "approval_policy_version": "release-policy/v7",
        },
    )
    assert response.status_code == 202
    event = client.get(f"/v1/audit/{response.json()['event_id']}").json()
    assert event["actor"] == "local-demo-service"
    assert event["action"] == "release-approved"
    assert event["decision"] == "allowed"
    assert event["metadata"]["approval_policy_version"] == "release-policy/v7"


def test_post_then_read_back_round_trips_all_fields(client: TestClient) -> None:
    body = sample_event(event_id="audit-event-99")
    accepted = client.post("/v1/audit", json=body)
    assert accepted.status_code == 202
    assert accepted.json()["event_id"] == "audit-event-99"

    resp = client.get("/v1/audit")
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) == 1
    got = events[0]

    # Every SPEC §6 AuditEvent field is preserved on read-back.
    assert got["action"] == body["action"]
    assert got["actor"] == body["actor"]
    assert got["decision"] == body["decision"]
    assert got["redacted_prompt"] == body["redacted_prompt"]
    assert got["redacted_response"] == body["redacted_response"]
    assert got["resource"] == body["resource"]
    assert got["trace_id"] == body["trace_id"]
    assert got["span_id"] == body["span_id"]
    assert got["correlation_id"] == body["correlation_id"]
    assert got["run_id"] == body["run_id"]
    assert got["event_id"] == body["event_id"]
    assert got["schema_version"] == "audit-event/v2"
    assert got["metadata"] == body["metadata"]

    # Citation fields mirror the Rsk1 Citation dataclass.
    cit = got["citations"][0]
    src = body["citations"][0]
    for key in (
        "source_id",
        "regulator",
        "jurisdiction",
        "title",
        "url",
        "version",
        "page",
        "snippet",
        "score",
    ):
        assert cit[key] == src[key]


def test_read_back_newest_first(client: TestClient) -> None:
    client.post("/v1/audit", json=sample_event(action="ask"))
    client.post("/v1/audit", json=sample_event(action="checklist"))
    client.post("/v1/audit", json=sample_event(action="testcases"))

    events = client.get("/v1/audit").json()
    assert [e["action"] for e in events] == ["testcases", "checklist", "ask"]


def test_read_back_filters_by_actor_and_action(client: TestClient) -> None:
    client.post("/v1/audit", json=sample_event(actor="alice", action="ask"))
    client.post("/v1/audit", json=sample_event(actor="bob", action="ask"))
    client.post("/v1/audit", json=sample_event(actor="alice", action="checklist"))

    by_actor = client.get("/v1/audit", params={"actor": "alice"}).json()
    assert {e["actor"] for e in by_actor} == {"alice"}
    assert len(by_actor) == 2

    by_action = client.get("/v1/audit", params={"action": "ask"}).json()
    assert {e["action"] for e in by_action} == {"ask"}
    assert len(by_action) == 2

    both = client.get("/v1/audit", params={"actor": "alice", "action": "checklist"}).json()
    assert len(both) == 1
    assert both[0]["actor"] == "alice"
    assert both[0]["action"] == "checklist"


def test_read_back_limit_is_enforced(client: TestClient) -> None:
    for _ in range(5):
        client.post("/v1/audit", json=sample_event())
    events = client.get("/v1/audit", params={"limit": 2}).json()
    assert len(events) == 2


def test_limit_out_of_range_rejected(client: TestClient) -> None:
    assert client.get("/v1/audit", params={"limit": 0}).status_code == 422
    assert client.get("/v1/audit", params={"limit": 100000}).status_code == 422


def test_decision_enum_validated(client: TestClient) -> None:
    bad = sample_event()
    bad["decision"] = "approved"  # not a Decision value
    assert client.post("/v1/audit", json=bad).status_code == 422


def test_minimal_event_uses_defaults(client: TestClient) -> None:
    minimal = {
        "action": "ask",
        "actor": "svc-account",
        "decision": "blocked",
        "redacted_prompt": "p",
        "redacted_response": "",
    }
    assert client.post("/v1/audit", json=minimal).status_code == 202
    got = client.get("/v1/audit").json()[0]
    assert got["resource"] == "compliance-advisory"
    assert got["citations"] == []
    assert got["metadata"] == {}
    assert got["trace_id"] is None
    assert got["span_id"] is None
    assert got["correlation_id"] is None
    assert got["schema_version"] == "audit-event/v2"
    assert got["timestamp"]  # auto-populated ISO string
    assert got["event_id"].startswith("audit-")


def test_legacy_hrz4_summary_detail_payload_is_upgraded(client: TestClient) -> None:
    legacy = {
        "action": "gate",
        "actor": "model-risk-service",
        "decision": "blocked",
        "summary": "gate FAIL for model@v1:golden",
        "detail": "model@v1",
        "resource": "ai-quality",
    }
    assert client.post("/v1/audit", json=legacy).status_code == 202
    got = client.get("/v1/audit").json()[0]
    assert got["redacted_prompt"] == legacy["summary"]
    assert got["redacted_response"] == legacy["detail"]


def test_idempotency_key_retries_store_one_resolvable_event(client: TestClient) -> None:
    headers = {"Idempotency-Key": "release-audit-42"}
    first = client.post("/v1/audit", json=sample_event(), headers=headers)
    second = client.post("/v1/audit", json=sample_event(), headers=headers)

    assert first.status_code == second.status_code == 202
    assert first.json()["event_id"] == second.json()["event_id"]
    events = client.get("/v1/audit").json()
    assert len(events) == 1
    resolved = client.get(f"/v1/audit/{first.json()['event_id']}")
    assert resolved.status_code == 200
    assert resolved.json()["event_id"] == first.json()["event_id"]


def test_conflicting_idempotency_key_reuse_is_rejected(client: TestClient) -> None:
    headers = {"Idempotency-Key": "release-audit-42"}
    first = client.post("/v1/audit", json=sample_event(action="gate"), headers=headers)
    assert first.status_code == 202

    conflict = client.post(
        "/v1/audit",
        json=sample_event(action="different"),
        headers=headers,
    )

    assert conflict.status_code == 409


def test_duplicate_event_id_with_different_payload_is_rejected(client: TestClient) -> None:
    assert (
        client.post(
            "/v1/audit",
            json=sample_event(action="gate", event_id="stable-event"),
        ).status_code
        == 202
    )

    conflict = client.post(
        "/v1/audit",
        json=sample_event(action="different", event_id="stable-event"),
    )

    assert conflict.status_code == 409


def test_a_tampered_store_refuses_writes_with_503_instead_of_laundering_them(
    tmp_path: Path, settings: Settings
) -> None:
    """Fail closed at the HTTP seam too: accepting the write would re-anchor the tamper.

    RED before the append-time anchor check: this POST returned 202 and the very act of
    accepting it re-anchored the forged prune, so the next `audit verify` came back clean.
    """
    db = tmp_path / "audit.db"
    anchor = tmp_path / "elsewhere.anchor.json"
    settings = replace(settings, local=LocalSettings(audit_path=str(db), anchor_path=str(anchor)))
    with TestClient(create_app(settings), client=LOOPBACK_PEER) as client:
        for n in range(4):
            assert client.post("/v1/audit", json=sample_event(event_id=f"seed-{n}")).status_code

        with sqlite3.connect(str(db)) as raw:  # forged prune: no trigger dropped
            seq, entry = raw.execute(
                "SELECT seq, entry_hash FROM audit_log ORDER BY seq LIMIT 1"
            ).fetchone()
            raw.execute(
                "UPDATE audit_chain_state SET prune_open = 1, pruned_seq = ?, pruned_hash = ? "
                "WHERE id = 1",
                (seq, entry),
            )
            raw.execute("DELETE FROM audit_log WHERE seq <= ?", (seq,))
            raw.execute("UPDATE audit_chain_state SET prune_open = 0 WHERE id = 1")
        anchored_before = anchor.read_text(encoding="utf-8")

        response = client.post("/v1/audit", json=sample_event(event_id="after-tamper"))

    assert response.status_code == 503
    assert "writes refused" in response.json()["detail"]
    assert anchor.read_text(encoding="utf-8") == anchored_before
