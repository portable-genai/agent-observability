"""Shared test helpers (imported by test modules; not a conftest)."""

from __future__ import annotations


def sample_event(
    *,
    actor: str = "analyst@bank.example",
    action: str = "ask",
    decision: str = "allowed",
    event_id: str = "",
) -> dict[str, object]:
    """A canonical AuditEvent body, shaped exactly like compliance-advisory's
    to_jsonable(AuditEvent).
    """
    return {
        "action": action,
        "actor": actor,
        "decision": decision,
        "redacted_prompt": "What does MAS require for [REDACTED] cloud outsourcing?",
        "redacted_response": "MAS Notice 658 requires ... (see citation).",
        "citations": [
            {
                "source_id": "mas-658-2024",
                "regulator": "MAS",
                "jurisdiction": "SG",
                "title": "MAS Notice 658",
                "url": "https://www.mas.gov.sg/notice-658",
                "version": "2024-06",
                "page": 12,
                "snippet": "Outsourcing arrangements must ...",
                "score": 0.91,
            }
        ],
        "resource": "compliance-advisory",
        "trace_id": "0af7651916cd43dd8448eb211c80319c",
        "span_id": "b7ad6b7169203331",
        "correlation_id": "invocation-42",
        "run_id": "eval-run-17",
        "event_id": event_id,
        "schema_version": "audit-event/v2",
        "timestamp": "2026-06-20T03:21:00+00:00",
        "metadata": {"tokens_in": "412", "tokens_out": "188", "latency_ms": "1240"},
    }
