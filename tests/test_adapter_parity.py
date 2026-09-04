"""Contract: the ``local`` and ``onprem`` adapters are structural parity of the port.

For the one persistence port agent-observability declares (``AuditSinkPort``), this iterates the
adapter map and, for both the ``onprem`` and ``local`` profiles, imports + constructs the bound
class (which must build cleanly with **no Google Cloud SDK** installed), then asserts:

  1. the constructed instance satisfies its runtime_checkable Protocol (isinstance), and
  2. every method the Protocol declares actually exists on the instance.

It additionally proves the two profiles' distinct contracts:

* ``onprem`` is the fail-fast Google Distributed Cloud migration target: every method
  raises ``NotImplementedError``, and
* ``local`` is a WORKING offline stack: the same port records and reads back in-process,
  with WORM (append-only, newest-first) semantics and page-level citation provenance.

This is the proof of the ports-and-adapters / no-lock-in promise (P-02): the on-prem
migration target and the offline local stack implement the exact same interface as the
managed GCP stack. The GCP adapter also constructs with NO google-cloud-logging installed
(its SDK import is lazy).
"""

from __future__ import annotations

import importlib

import pytest

from observability.adapters.gcp.cloud_logging_audit import CloudLoggingAuditAdapter
from observability.adapters.local.audit import LocalAppendOnlyAuditAdapter
from observability.config import LocalSettings, ProfileError, Settings
from observability.container import Container
from observability.models import AuditEvent, Citation, Decision
from observability.ports import AuditSinkPort

# Every port name in settings.adapters mapped to its Protocol.
PORT_PROTOCOLS: dict[str, type] = {
    "audit": AuditSinkPort,
}

# Profiles whose adapters must construct + satisfy the Protocols with no GCP SDK.
SDK_FREE_PROFILES = ("onprem", "local")

_BINDINGS = {
    "audit": {
        "gcp": "observability.adapters.gcp.cloud_logging_audit:CloudLoggingAuditAdapter",
        "local": "observability.adapters.local.audit:LocalAppendOnlyAuditAdapter",
        "onprem": "observability.adapters.onprem.audit:OnPremAuditAdapter",
    }
}


def _settings(profile: str) -> Settings:
    return Settings(
        project_id="test-project",
        profile=profile,
        local=LocalSettings(audit_path=":memory:"),
        adapters=_BINDINGS,
    )


def _instantiate(dotted: str, settings: Settings) -> object:
    module_path, _, class_name = dotted.partition(":")
    cls = getattr(importlib.import_module(module_path), class_name)
    return cls(settings)


def _event(
    actor: str = "a", action: str = "ask", *, decision: Decision = Decision.ALLOWED
) -> AuditEvent:
    return AuditEvent(
        action=action,
        actor=actor,
        decision=decision,
        redacted_prompt="p",
        redacted_response="r",
        citations=(
            Citation(source_id="s", regulator="MAS", jurisdiction="SG", title="t", url="u", page=3),
        ),
    )


# --------------------------------------------------------------------------- #
# Contract parity (local + onprem), plus the lazy-import GCP adapter
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("profile", SDK_FREE_PROFILES)
@pytest.mark.parametrize("port_name", sorted(PORT_PROTOCOLS))
def test_adapter_satisfies_protocol(profile: str, port_name: str) -> None:
    settings = _settings(profile)
    protocol = PORT_PROTOCOLS[port_name]
    dotted = _BINDINGS[port_name][profile]
    adapter = _instantiate(dotted, settings)

    # 1. Structural conformance via runtime_checkable Protocol.
    assert isinstance(adapter, protocol), f"{dotted} does not satisfy {protocol.__name__}"

    # 2. Every declared Protocol member exists on the class (via the MRO).
    members = {m for m in getattr(protocol, "__protocol_attrs__", set()) if not m.startswith("_")}
    declared = set().union(*(vars(klass) for klass in type(adapter).__mro__))
    for member in members:
        assert member in declared, f"{dotted} is missing port method '{member}'"


def test_adapter_map_is_exact_and_unknown_profile_fails_closed() -> None:
    configured = Settings.load("config/settings.yaml")
    assert set(configured.adapters) == set(PORT_PROTOCOLS)
    assert all(
        set(bindings) == {"local", "gcp", "onprem"} for bindings in configured.adapters.values()
    )

    # An unbindable profile is now refused when the CONFIGURATION is built, one layer earlier
    # than the container lookup below, so no code path can reach an app with a typo'd profile
    # whose exact-match posture comparisons all silently miss.
    with pytest.raises(ProfileError, match="unknown OBSERVABILITY_PROFILE"):
        _settings("misspelled")


def test_the_container_still_fails_closed_on_a_port_with_no_binding() -> None:
    """The container's own fail-closed, exercised with a VALID profile and a gap in the map."""
    settings = Settings(
        region="asia-southeast1",
        profile="onprem",
        local=LocalSettings(audit_path=":memory:"),
        adapters={"audit": {"local": _BINDINGS["audit"]["local"]}},
    )
    with pytest.raises(KeyError, match="profile 'onprem'"):
        _ = Container(settings).audit


def test_both_sdk_free_families_construct_with_single_settings_arg() -> None:
    for profile in SDK_FREE_PROFILES:
        dotted = _BINDINGS["audit"][profile]
        assert _instantiate(dotted, _settings(profile)) is not None


def test_gcp_adapter_constructs_without_sdk(settings: Settings) -> None:
    # The GCP adapter imports cleanly + constructs with NO google-cloud-logging present
    # (lazy import) and is a structural subtype of the port.
    assert isinstance(CloudLoggingAuditAdapter(settings), AuditSinkPort)


def test_all_protocols_are_runtime_checkable() -> None:
    for protocol in PORT_PROTOCOLS.values():
        assert getattr(protocol, "_is_runtime_protocol", False), (
            f"{protocol.__name__} must be @runtime_checkable"
        )


# --------------------------------------------------------------------------- #
# onprem is fail-fast
# --------------------------------------------------------------------------- #
def test_onprem_audit_fails_fast() -> None:
    settings = _settings("onprem")
    adapter = _instantiate(_BINDINGS["audit"]["onprem"], settings)
    with pytest.raises(NotImplementedError):
        adapter.record(_event())  # type: ignore[attr-defined]
    with pytest.raises(NotImplementedError):
        adapter.read_recent()  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# local is a WORKING WORM store (drives the real adapter, no fakes)
# --------------------------------------------------------------------------- #
def test_local_is_append_only_and_newest_first(audit: LocalAppendOnlyAuditAdapter) -> None:
    audit.record(_event(action="ask"))
    audit.record(_event(action="checklist"))
    recent = audit.read_recent(limit=10)
    assert [e.action for e in recent] == ["checklist", "ask"]


def test_local_round_trips_citation_provenance(audit: LocalAppendOnlyAuditAdapter) -> None:
    audit.record(_event())
    got = audit.read_recent(limit=1)[0]
    assert got.citations and got.citations[0].page == 3
    assert got.citations[0].source_id == "s"


def test_local_ring_buffer_bounded() -> None:
    small = Settings(profile="local", max_events=3, local=LocalSettings(audit_path=":memory:"))
    adapter = LocalAppendOnlyAuditAdapter(small)
    for i in range(10):
        adapter.record(_event(actor=f"u{i}"))
    recent = adapter.read_recent(limit=100)
    assert len(recent) == 3
    assert [e.actor for e in recent] == ["u9", "u8", "u7"]


def test_local_filters(audit: LocalAppendOnlyAuditAdapter) -> None:
    audit.record(_event(actor="alice", action="ask"))
    audit.record(_event(actor="bob", action="ask"))
    assert len(audit.read_recent(actor="alice")) == 1
    assert len(audit.read_recent(action="ask")) == 2


def test_local_seed_provides_real_corpus(audit: LocalAppendOnlyAuditAdapter) -> None:
    n = audit.seed()
    assert n >= 1
    recent = audit.read_recent(limit=n)
    assert recent, "seeded local WORM store returned nothing"
    # The seeded corpus carries page-level citations (compliance provenance) and a
    # deterministically blocked prompt-injection event.
    assert any(c.page is not None for e in recent for c in e.citations)
    assert any(e.decision is Decision.BLOCKED for e in recent)
