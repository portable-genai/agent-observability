"""Prove every eval metric can go RED: a degraded audit round trip must score below threshold.

Hrz5 has no model to promote, so its metrics are audit-integrity invariants rather than judge
scores. That changes nothing about falsification: all four sit at a 1.00 threshold, and a
metric pinned at 1.00 that has never been observed failing is indistinguishable from no check
at all. Each scorer is imported from ``eval/run_eval.py`` and fed the same round trip twice,
once as the store returned it and once carrying exactly the defect the metric exists to catch.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from agent_eval_kit import assert_can_go_red
from eval.run_eval import (
    DEFAULT_DATASET,
    THRESHOLDS,
    _adapter,
    _event_for,
    load_golden,
    score_citation_provenance,
    score_newest_first_order,
    score_redaction_preserved,
    score_write_read_parity,
)

from observability.models import AuditEvent

#: An example that must cite something, so citation_provenance scores a real expectation.
_EXAMPLE = next(e for e in load_golden(DEFAULT_DATASET) if e.must_cite_source_ids)


@pytest.fixture(scope="module")
def round_trip() -> tuple[AuditEvent, AuditEvent]:
    """One real write and its read-back off the local WORM adapter: the green observation."""
    adapter = _adapter()
    written = _event_for(_EXAMPLE, ts=datetime(2026, 6, 20, 3, 0, 0, tzinfo=UTC))
    adapter.record(written)
    stored = adapter.read_recent(actor=_EXAMPLE.actor, action=_EXAMPLE.action, limit=1)
    assert stored, "the proof needs an event that actually read back"
    return stored[0], written


def test_write_read_parity_can_go_red(round_trip: tuple[AuditEvent, AuditEvent]) -> None:
    stored, written = round_trip
    assert_can_go_red(
        lambda got: score_write_read_parity(got, written),
        green=stored,
        red=replace(stored, actor="someone-who-never-acted"),  # attribution did not survive
        threshold=THRESHOLDS["write_read_parity"],
        metric="write_read_parity",
    )


def test_citation_provenance_can_go_red(round_trip: tuple[AuditEvent, AuditEvent]) -> None:
    stored, _ = round_trip
    assert_can_go_red(
        lambda got: score_citation_provenance(got, tuple(_EXAMPLE.must_cite_source_ids)),
        green=stored,
        red=replace(stored, citations=()),  # the evidence links were dropped by the store
        threshold=THRESHOLDS["citation_provenance"],
        metric="citation_provenance",
    )


def test_redaction_preserved_can_go_red(round_trip: tuple[AuditEvent, AuditEvent]) -> None:
    stored, written = round_trip
    assert_can_go_red(
        lambda got: score_redaction_preserved(got, written),
        green=stored,
        red=replace(stored, redacted_prompt="applicant NRIC S1234567D"),  # raw PII in the trail
        threshold=THRESHOLDS["redaction_preserved"],
        metric="redaction_preserved",
    )


def test_newest_first_order_can_go_red() -> None:
    """Append-only, newest-first: a reordered or truncated read is not a valid trail."""
    expected = ["trace-3", "trace-2", "trace-1"]
    assert_can_go_red(
        lambda got: score_newest_first_order(got, expected),
        green=list(expected),
        red=["trace-1", "trace-2", "trace-3"],  # oldest-first: the ordering guarantee is gone
        threshold=THRESHOLDS["newest_first_order"],
        metric="newest_first_order",
    )
