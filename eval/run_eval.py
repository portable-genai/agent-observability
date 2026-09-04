#!/usr/bin/env python3
"""Offline evaluation gate for agent-observability — rule R2 / P-08.

This is the **promotion gate**: CI runs it on every change and the build fails if the
audit store stops satisfying its compliance invariants. Unlike a QA assistant, agent-observability's
correctness is about the *integrity of the immutable trail*, so the metrics check the
WORM round-trip rather than answer quality::

    write_read_parity    >= 1.00   every written event reads back field-for-field
    citation_provenance  >= 1.00   stored citations keep page-level provenance
    redaction_preserved  >= 1.00   only redacted_* fields are stored (no raw-PII column)
    newest_first_order    >= 1.00   read-back is newest-first and append-only

The gate drives the **local** ``LocalAppendOnlyAuditAdapter`` (the SDK-free SQLite WORM
stand-in) against an in-memory store, with **no GCP credentials and no Google Cloud SDK**.
The domain models and the local adapter are pure-stdlib, so this runs in the local / test
profile offline. Exit code is ``0`` iff every metric meets its threshold.

Usage::

    python eval/run_eval.py                       # offline gate (CI)
    python eval/run_eval.py --dataset path.jsonl  # custom golden audit set
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

# Pure-stdlib domain + the SDK-free local adapter: no Google Cloud SDK needed.
from observability.adapters.local.audit import LocalAppendOnlyAuditAdapter
from observability.config import LocalSettings, Settings
from observability.models import AuditEvent, Citation, Decision

THRESHOLDS: dict[str, float] = {
    "write_read_parity": 1.00,
    "citation_provenance": 1.00,
    "redaction_preserved": 1.00,
    "newest_first_order": 1.00,
}

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = _REPO_ROOT / "eval" / "datasets" / "golden_audit.jsonl"


@dataclass(frozen=True, slots=True)
class GoldenEvent:
    id: str
    action: str
    actor: str
    decision: str
    redacted_prompt: str
    redacted_response: str
    must_cite_source_ids: tuple[str, ...]
    page: int | None


def load_golden(path: Path) -> list[GoldenEvent]:
    examples: list[GoldenEvent] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise SystemExit(f"{path}:{lineno}: invalid JSON: {exc}") from exc
        examples.append(
            GoldenEvent(
                id=str(obj.get("id", f"example-{lineno}")),
                action=str(obj["action"]),
                actor=str(obj["actor"]),
                decision=str(obj.get("decision", "allowed")),
                redacted_prompt=str(obj.get("redacted_prompt", "")),
                redacted_response=str(obj.get("redacted_response", "")),
                must_cite_source_ids=tuple(obj.get("must_cite_source_ids", []) or ()),
                page=(int(obj["page"]) if obj.get("page") is not None else None),
            )
        )
    if not examples:
        raise SystemExit(f"{path}: golden dataset is empty")
    return examples


def _event_for(example: GoldenEvent, *, ts: datetime) -> AuditEvent:
    citations = tuple(
        Citation(
            source_id=sid,
            regulator="MAS",
            jurisdiction="SG",
            title=f"Source {sid}",
            url=f"https://example.test/{sid}",
            version="2024",
            page=example.page if example.page is not None else 1,
            snippet="Applicable supervisory expectation.",
            score=0.9,
        )
        for sid in example.must_cite_source_ids
    )
    return AuditEvent(
        action=example.action,
        actor=example.actor,
        decision=Decision(example.decision),
        redacted_prompt=example.redacted_prompt,
        redacted_response=example.redacted_response,
        citations=citations,
        trace_id=f"trace-{example.id}",
        timestamp=ts,
        metadata={"tokens_in": "100", "tokens_out": "50"},
    )


@dataclass
class _PerMetric:
    scores: list[float] = field(default_factory=list)

    @property
    def mean(self) -> float:
        return sum(self.scores) / len(self.scores) if self.scores else 0.0


def _adapter() -> LocalAppendOnlyAuditAdapter:
    settings = Settings(profile="local", local=LocalSettings(audit_path=":memory:"))
    return LocalAppendOnlyAuditAdapter(settings)


def score_write_read_parity(stored: AuditEvent | None, written: AuditEvent) -> float:
    """1.0 only when the event read back is field-for-field the event that was written."""
    return 1.0 if stored is not None and _same(stored, written) else 0.0


def score_citation_provenance(stored: AuditEvent | None, must_cite: tuple[str, ...]) -> float:
    """Stored citations must be exactly the expected sources, each keeping its page."""
    if not must_cite:
        return 1.0  # nothing was expected to be cited
    if stored is None:
        return 0.0
    exact = {c.source_id for c in stored.citations} == set(must_cite)
    return 1.0 if exact and all(c.page is not None for c in stored.citations) else 0.0


def score_redaction_preserved(stored: AuditEvent | None, written: AuditEvent) -> float:
    """Only redacted_* text survives the store: raw PII never had a column to land in."""
    return (
        1.0
        if stored is not None
        and stored.redacted_prompt == written.redacted_prompt
        and stored.redacted_response == written.redacted_response
        else 0.0
    )


def score_newest_first_order(got_order: list[str], expected_order: list[str]) -> float:
    """The trail reads back newest-first and append-only, with nothing dropped or reordered."""
    return 1.0 if got_order == expected_order else 0.0


def run_offline(dataset: Path) -> tuple[dict[str, float], bool]:
    examples = load_golden(dataset)
    adapter = _adapter()
    agg: dict[str, _PerMetric] = {m: _PerMetric() for m in THRESHOLDS}

    base = datetime(2026, 6, 20, 3, 0, 0, tzinfo=UTC)
    written: list[AuditEvent] = []
    for i, example in enumerate(examples):
        event = _event_for(example, ts=base.replace(second=i % 60, minute=i // 60))
        adapter.record(event)
        written.append(event)

        got = adapter.read_recent(actor=example.actor, action=example.action, limit=1)
        match = got[0] if got else None

        agg["write_read_parity"].scores.append(score_write_read_parity(match, event))
        agg["citation_provenance"].scores.append(
            score_citation_provenance(match, tuple(example.must_cite_source_ids))
        )
        agg["redaction_preserved"].scores.append(score_redaction_preserved(match, event))

    # Append-only + newest-first across the whole written set.
    recent = adapter.read_recent(limit=len(examples) + 5)
    expected_order = [e.trace_id for e in reversed(written)]
    got_order = [e.trace_id for e in recent]
    agg["newest_first_order"].scores.append(score_newest_first_order(got_order, expected_order))

    scores = {m: round(agg[m].mean, 4) for m in THRESHOLDS}
    passed = all(scores[m] >= THRESHOLDS[m] for m in THRESHOLDS)
    return scores, passed


def _same(a: AuditEvent, b: AuditEvent) -> bool:
    return (
        a.action == b.action
        and a.actor == b.actor
        and a.decision == b.decision
        and a.redacted_prompt == b.redacted_prompt
        and a.redacted_response == b.redacted_response
        and a.trace_id == b.trace_id
        and tuple(c.source_id for c in a.citations) == tuple(c.source_id for c in b.citations)
    )


def print_report(scores: dict[str, float], passed: bool, dataset: Path, n: int) -> None:
    print("Evaluation report  (offline audit-integrity gate, no GCP creds)")
    print(f"  dataset : {dataset}")
    print(f"  events  : {n}\n")
    name_w = max(len(m) for m in scores)
    header = f"  {'metric'.ljust(name_w)}   score    threshold   result"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for metric, score in scores.items():
        threshold = THRESHOLDS[metric]
        status = "PASS" if score >= threshold else "FAIL"
        print(f"  {metric.ljust(name_w)}   {score:6.3f}   {threshold:7.2f}     {status}")
    print()
    print(f"  GATE: {'PASS' if passed else 'FAIL'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline audit-integrity eval gate for agent-observability (rule R2 / P-08).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
        help="Path to the JSONL golden audit set (default: eval/datasets/golden_audit.jsonl).",
    )
    args = parser.parse_args(argv)
    dataset: Path = args.dataset
    if not dataset.exists():
        print(f"error: dataset not found: {dataset}", file=sys.stderr)
        return 2

    examples = load_golden(dataset)
    scores, passed = run_offline(dataset)
    print_report(scores, passed, dataset, len(examples))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
