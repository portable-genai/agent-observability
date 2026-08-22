#!/usr/bin/env python3
"""Bounded, executable portability proof for Hrz5.

This proof runs offline. It checks the complete adapter map, a real SQLite record/reopen
round trip, open JSON wire-format reload, SDK-free managed construction, fail-closed
on-premises behavior, an unknown profile selector refused when the configuration is built,
and the three-state profile resolution in which an UNSET selector is no choice at all.

It also proves the audit trail's own exit story: the chained local store exports to open
JSON Lines, restores into a fresh store, and re-verifies every hash link.

It does not claim live GCP behavior, a completed on-premises WORM store, managed-bucket
export/restore, identity portability, or portable trace/FinOps infrastructure.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from observability.config import (
    UNCONSENTED_PROFILE,
    LocalSettings,
    ProfileError,
    Settings,
    resolve_profile,
)
from observability.container import Container
from observability.models import AuditEvent, Citation, Decision
from observability.schemas import AuditEventModel
from observability.serialization import to_jsonable

_PROFILES = {"local", "gcp", "onprem"}
_PORTS = {"audit"}

# The proof intentionally exercises the default SDK-free SQLite runtime, even when the
# invoking shell has an emulator variable left over from another task.
os.environ.pop("FIRESTORE_EMULATOR_HOST", None)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"portability evidence mismatch: {message}")


def _settings(base: Settings, profile: str, audit_path: str) -> Settings:
    return Settings(
        project_id=base.project_id,
        region=base.region,
        profile=profile,
        max_events=base.max_events,
        logging=base.logging,
        finops=base.finops,
        local=LocalSettings(audit_path=audit_path),
        adapters=base.adapters,
    )


def _event() -> AuditEvent:
    return AuditEvent(
        action="ask",
        actor="auditor@bank.example",
        decision=Decision.ALLOWED,
        redacted_prompt="Review the fictional [REDACTED] control.",
        redacted_response="The fictional control is evidenced.",
        citations=(
            Citation(
                source_id="fictional-control",
                regulator="EXAMPLE",
                jurisdiction="SG",
                title="Fictional control",
                url="https://example.test/control",
                version="2026",
                page=7,
            ),
        ),
        trace_id="11111111111111111111111111111111",
        event_id="11111111-1111-4111-8111-111111111111",
        timestamp=datetime(2026, 7, 27, 12, 0, tzinfo=UTC),
        metadata={"tokens_in": "10", "tokens_out": "5", "latency_ms": "20"},
    )


def main() -> int:
    print("Hrz5 bounded portability proof")
    base = Settings.load()
    _require(set(base.adapters) == _PORTS, "port set")
    _require(
        all(set(bindings) == _PROFILES for bindings in base.adapters.values()),
        "profile set",
    )
    print("PASS profile map: local, gcp and onprem are explicit for the audit port")

    with tempfile.TemporaryDirectory(prefix="hrz5-portability-") as tmp:
        audit_path = str(Path(tmp) / "audit.db")
        event = _event()
        local = Container(_settings(base, "local", audit_path)).audit
        local.record(event)

        reopened = Container(_settings(base, "local", audit_path)).audit
        events = reopened.read_recent(limit=1)
        _require(len(events) == 1, "local reopen count")
        _require(to_jsonable(events[0]) == to_jsonable(event), "local reopen parity")
        print("PASS runtime seam: a fresh local adapter reopens the same audit record")

        exported = json.dumps(to_jsonable(events[0]), sort_keys=True)
        reloaded = AuditEventModel.model_validate_json(exported).to_domain()
        _require(to_jsonable(reloaded) == to_jsonable(event), "JSON wire reload")
        print("PASS data contract: one audit event exports and reloads as open JSON")

        # Exit story for the audit trail itself: the whole chained store leaves as open
        # JSON Lines and reloads elsewhere with every hash link re-verified.
        dump = Path(tmp) / "trail.jsonl"
        _require(local.export_jsonl(dump) == 1, "export record count")
        # Line 1 is the anchor header the restore checks the arriving records against, so the
        # file carries one more line than it carries records.
        _require(len(dump.read_text(encoding="utf-8").splitlines()) == 2, "export line count")
        restored = Container(_settings(base, "local", str(Path(tmp) / "restored.db"))).audit
        _require(restored.import_jsonl(dump) == 1, "restore count")
        _require(restored.verify_chain().ok, "restored chain verifies")
        _require(local.verify_chain().ok, "source chain verifies")
        print("PASS tamper evidence: the chained trail exports, restores and re-verifies")

    managed = Container(_settings(base, "gcp", ":memory:"))
    _ = managed.audit
    print("PASS managed seam: the GCP adapter constructs without an eager SDK call")

    onprem = Container(_settings(base, "onprem", ":memory:"))
    try:
        onprem.audit.record(_event())
    except NotImplementedError:
        print("PASS exit boundary: the unconfigured on-premises sink fails closed")
    else:
        raise AssertionError("on-premises audit sink did not fail closed")

    # The selector is refused when the Settings object is BUILT, not when an adapter is
    # looked up: `Settings.__post_init__` validates the profile, so a mis-capitalised
    # `Local` cannot produce a configuration at all. Unvalidated, it would reach the container
    # and then the app, where every posture comparison is an exact `== "local"` that a typo
    # silently loses, and a LAN peer gets 200 where an exactly-`local` run gets 503.
    for unknown in ("misspelled", "Local"):
        try:
            _ = _settings(base, unknown, ":memory:")
        except ProfileError:
            print(f"PASS selector: profile {unknown!r} is refused when Settings is built")
        else:
            raise AssertionError(f"unknown profile {unknown!r} did not fail closed")

    # And the profile is resolved in THREE states, so a run nobody configured is not read as
    # consent to the local profile's zero-secret WORM ingest.
    unconsented = resolve_profile({})
    _require(unconsented.explicit is False, "unset profile is not explicit")
    _require(unconsented.exposure_profile == UNCONSENTED_PROFILE, "unset relaxation profile")
    _require(unconsented.exposure_profile not in _PROFILES, "unconsented is not a runtime profile")
    _require(unconsented.bind_profile == "local", "unset run stays bound to loopback")
    chosen = resolve_profile({"OBSERVABILITY_PROFILE": "local"})
    _require(chosen.explicit is True, "a deliberate profile is explicit")
    _require(chosen.exposure_profile == "local", "a deliberate profile is carried through")
    print("PASS selector: an UNSET profile is no choice, not a chosen 'local'")

    print(
        "LIMITS not proved here: live GCP, complete on-premises WORM, managed-bucket "
        "migration, identity portability, or trace/FinOps portability."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
