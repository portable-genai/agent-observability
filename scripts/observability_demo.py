"""Presenter-controlled, assertion-backed walkthrough of Hrz5 Observability.

Hrz5 is a platform service with a REST API and CLI, not a browser UI. This demo drives
the real SDK-free ``local`` adapter against an ephemeral file-backed SQLite store. It
uses only clearly fictional records and needs no cloud credentials, API key or emulator.

The presenter controls the pace. ``DEMO_AUTO=1`` disables prompts and turns the same
walkthrough into a CI self-test. ``DEMO_OUT`` selects the JSON evidence artifact path.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AUTO = os.environ.get("DEMO_AUTO") == "1"
OUT_PATH = Path(os.environ.get("DEMO_OUT", "observability_demo.json"))

_TMP = Path(tempfile.mkdtemp(prefix="observability-demo-")) / "audit.db"
os.environ["OBSERVABILITY_PROFILE"] = "local"
os.environ["OBSERVABILITY_LOCAL_AUDIT"] = str(_TMP)
os.environ.pop("FIRESTORE_EMULATOR_HOST", None)

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from observability import __version__  # noqa: E402
from observability.adapters.local.audit import LocalAppendOnlyAuditAdapter  # noqa: E402
from observability.config import Settings  # noqa: E402
from observability.models import AuditEvent, Citation, Decision  # noqa: E402
from observability.serialization import to_jsonable  # noqa: E402

RULE = "=" * 78
ACTOR = "analyst@bank.example"


def _pause(prompt: str) -> None:
    if AUTO:
        return
    try:
        input(prompt)
    except EOFError:
        time.sleep(0.2)


def _step(n: int, title: str, narration: str) -> None:
    print(f"\n{RULE}\nStep {n}/6. {title}\n{RULE}")
    print(narration)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"demo evidence mismatch: {message}")


def _identity(event: AuditEvent) -> tuple[str, str, str | None]:
    return (event.actor, event.action, event.trace_id)


def _fmt_citation(citation: Citation) -> str:
    page = f" p.{citation.page}" if citation.page is not None else ""
    version = f" {citation.version}" if citation.version and citation.version != "unknown" else ""
    return f"[{citation.source_id}, {citation.regulator}{version}{page}] {citation.url}"


def _print_event(event: AuditEvent) -> None:
    print(f"  [{event.decision.value.upper()}] {event.action}  actor={event.actor}")
    print(f"    at: {event.timestamp.isoformat()}  trace_id={event.trace_id or '-'}")
    print(f"    prompt:   {event.redacted_prompt}")
    print(f"    response: {event.redacted_response or '(blocked; no response emitted)'}")
    for citation in event.citations:
        print(f"    cite:     {_fmt_citation(citation)}")
    if event.metadata:
        rendered = ", ".join(f"{key}={value}" for key, value in sorted(event.metadata.items()))
        print(f"    finops:   {rendered}")


def _fresh_event() -> AuditEvent:
    return AuditEvent(
        action="ask",
        actor="auditor@bank.example",
        decision=Decision.ALLOWED,
        redacted_prompt=("Summarise the MAS outsourcing notification timeline for [REDACTED]."),
        redacted_response=("Notify MAS of material outsourcing; retain audit and access rights."),
        citations=(
            Citation(
                source_id="mas-trm-guidelines",
                regulator="MAS",
                jurisdiction="SG",
                title="MAS Technology Risk Management Guidelines",
                url="https://example.test/mas/trm",
                version="2021",
                page=44,
                snippet=("The institution should notify the Authority of material outsourcing."),
                score=0.9,
            ),
        ),
        trace_id="3df7651916cd43dd8448eb211c80319f",
        timestamp=datetime(2026, 6, 20, 3, 24, tzinfo=UTC),
        metadata={"tokens_in": "508", "tokens_out": "201", "latency_ms": "1390"},
    )


def main() -> int:
    settings = Settings.load()
    print(RULE)
    print("Hrz5 Agent Observability, Audit & FinOps - guided local walkthrough")
    print(RULE)
    print(
        "Profile : local (SDK-free bounded SQLite audit buffer)\n"
        f"Store   : {_TMP}\n"
        f"Region  : {settings.region} (configurable; defaults to us-central1)\n"
        "Note    : synthetic, fictional corpus; no cloud credentials or API key."
    )

    audit = LocalAppendOnlyAuditAdapter(settings)
    artifact: dict[str, Any] = {
        "service": "agent-observability",
        "version": __version__,
        "profile": settings.profile,
        "region": settings.region,
        "synthetic": True,
        "steps": [],
    }

    _step(
        1,
        "Seed the local audit buffer",
        "Seed three already-redacted synthetic events through the shipped local adapter.",
    )
    appended = audit.seed()
    retained = audit.count()
    _require(appended == 3, "seed count")
    _require(retained == 3, "retained seed count")
    print(f"\n  appended={appended}; retained={retained}.")
    artifact["steps"].append({"step": "seed", "appended": appended, "retained": retained})
    _pause("\n  [Enter] to continue after reviewing the seed result... ")

    _step(
        2,
        "Regulator pull with page provenance",
        "Read newest-first and preserve the exact page-level citations supplied upstream.",
    )
    recent = audit.read_recent(limit=50)
    _require(
        [event.trace_id for event in recent]
        == [
            "2cf7651916cd43dd8448eb211c80319e",
            "1bf7651916cd43dd8448eb211c80319d",
            "0af7651916cd43dd8448eb211c80319c",
        ],
        "newest-first seed order",
    )
    _require(
        all(citation.page is not None for event in recent for citation in event.citations),
        "citation page provenance",
    )
    print()
    for event in recent:
        _print_event(event)
    artifact["steps"].append(
        {"step": "regulator_pull", "events": [to_jsonable(event) for event in recent]}
    )
    _pause("\n  [Enter] to continue after reviewing the pull... ")

    _step(
        3,
        "Append and read back one exact record",
        "Append an already-redacted event and prove this retained window grows by one.",
    )
    before = audit.count()
    fresh = _fresh_event()
    audit.record(fresh)
    after = audit.count()
    latest = audit.read_recent(limit=1)
    _require(after == before + 1, "append count")
    _require(
        len(latest) == 1 and _identity(latest[0]) == _identity(fresh),
        "append read-back",
    )
    print(f"\n  retained {before} -> {after}; latest trace={latest[0].trace_id}.")
    artifact["steps"].append(
        {
            "step": "append",
            "before": before,
            "after": after,
            "event": to_jsonable(latest[0]),
        }
    )
    _pause("\n  [Enter] to continue after reviewing the append result... ")

    _step(
        4,
        "Scoped regulator request",
        f"Filter the same trail to the exact actor {ACTOR}.",
    )
    scoped = audit.read_recent(actor=ACTOR, limit=50)
    _require(len(scoped) == 2, "scoped actor count")
    _require(all(event.actor == ACTOR for event in scoped), "scoped actor filter")
    print(f"\n  {len(scoped)} event(s) for actor={ACTOR}:")
    for event in scoped:
        _print_event(event)
    artifact["steps"].append(
        {
            "step": "actor_filter",
            "actor": ACTOR,
            "events": [to_jsonable(event) for event in scoped],
        }
    )
    _pause("\n  [Enter] to continue after reviewing the scoped result... ")

    _step(
        5,
        "Deterministic FinOps rollup",
        "Aggregate token and latency metadata from the retained synthetic trail.",
    )
    rollup: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"calls": 0, "tokens_in": 0, "tokens_out": 0, "max_latency_ms": 0}
    )
    for event in audit.read_recent(limit=500):
        row = rollup[(event.actor, event.action)]
        row["calls"] += 1
        row["tokens_in"] += int(event.metadata.get("tokens_in", "0") or 0)
        row["tokens_out"] += int(event.metadata.get("tokens_out", "0") or 0)
        row["max_latency_ms"] = max(
            row["max_latency_ms"],
            int(event.metadata.get("latency_ms", "0") or 0),
        )
    print(f"\n  {'actor':<24}{'action':<12}{'calls':>6}{'tok_in':>9}{'tok_out':>9}{'max_ms':>9}")
    for (actor, action), row in sorted(rollup.items()):
        print(
            f"  {actor:<24}{action:<12}{row['calls']:>6}"
            f"{row['tokens_in']:>9}{row['tokens_out']:>9}{row['max_latency_ms']:>9}"
        )
    totals = {
        "calls": sum(row["calls"] for row in rollup.values()),
        "tokens_in": sum(row["tokens_in"] for row in rollup.values()),
        "tokens_out": sum(row["tokens_out"] for row in rollup.values()),
        "max_latency_ms": max(row["max_latency_ms"] for row in rollup.values()),
    }
    _require(
        totals
        == {
            "calls": 4,
            "tokens_in": 1744,
            "tokens_out": 765,
            "max_latency_ms": 1390,
        },
        "FinOps totals",
    )
    artifact["steps"].append(
        {
            "step": "finops",
            "rows": {f"{actor}:{action}": row for (actor, action), row in sorted(rollup.items())},
            "totals": totals,
        }
    )
    _pause("\n  [Enter] to continue after reviewing the FinOps result... ")

    _step(
        6,
        "On-premises exit seam fails closed",
        "The unconfigured on-premises adapter must reject access, never fabricate a record.",
    )
    from observability.adapters.onprem.audit import OnPremAuditAdapter

    failed_closed = False
    try:
        OnPremAuditAdapter(settings).read_recent(limit=5)
    except NotImplementedError as exc:
        failed_closed = True
        print(f"\n  onprem.read_recent() -> NotImplementedError: {exc}")
    _require(failed_closed, "onprem fail-fast")
    artifact["steps"].append({"step": "onprem", "failed_closed": failed_closed})
    _pause("\n  [Enter] to finish after reviewing the exit result... ")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    print(f"\n{RULE}")
    print("Demo complete.")
    print(f"  local audit buffer: {str(_TMP)}")
    print(f"  evidence artifact : {str(OUT_PATH)}")
    print(
        "  Limit: local SQLite is a bounded demo buffer, not the managed locked "
        "WORM retention control."
    )
    print(RULE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
