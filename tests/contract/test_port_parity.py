"""Port-set drift guard: the port registry, the SHIPPED adapter map and the profile registry agree.

Three registries describe this service's hexagon and nothing at runtime compares them:

* the runtime_checkable Protocols exported by :mod:`observability.ports` (what a port IS),
* the ``adapters:`` map in ``config/settings.yaml`` (which class fills it, per profile), and
* :data:`observability.config.RUNTIME_PROFILES` (which profiles may be selected at all).

A port bound in ``settings.yaml`` but absent from the protocol map below is unenforced with a
green build. A Protocol added to ``ports/`` and never bound is a hexagon edge nobody can reach.
A profile admitted to ``RUNTIME_PROFILES`` with nothing bound to it loads, validates, and then
raises ``KeyError`` at the first port access in production. Every assertion here is therefore set
equality in BOTH directions: one direction alone lets a new port ship with no sovereign binding,
which is the omission that quietly reaches for the managed stack, and the other lets an orphan
adapter overstate coverage.

Why this file loads ``config/settings.yaml`` for every construction. The sibling suite
``tests/test_adapter_parity.py`` holds its own literal ``_BINDINGS`` table and builds adapters
from THAT, so its proofs are about a copy of the deployment map rather than the map the container
imports at boot. A dotted path renamed in the shipped file alone would leave that suite green.
Here the shipped file is the only source, and every binding it names is imported and constructed.

Scope note. This file guards the SETS and the constructibility of the shipped bindings. The WORM
behaviour of the ``local`` store and the fail-fast contract of ``onprem`` are proven next door in
``tests/test_adapter_parity.py`` and are deliberately not restated.
"""

from __future__ import annotations

from typing import Protocol, get_type_hints

import pytest

from observability import ports
from observability.config import RUNTIME_PROFILES, LocalSettings, Settings
from observability.container import Container, _load

CONFIG_PATH = "config/settings.yaml"

#: Every port name in ``settings.adapters`` mapped to its Protocol. Hand maintained on purpose:
#: the tests below fail loudly when it stops matching either registry it straddles.
#: agent-observability is a
#: control-plane service with ONE persistence port; that is the honest port set, not a shortfall.
PORT_PROTOCOLS: dict[str, type] = {
    "audit": ports.AuditSinkPort,
}

#: Port name -> the :class:`Container` attribute that serves it. A port with a binding and no
#: accessor is bound to something the service can never ask for.
PORT_ACCESSORS: dict[str, str] = {
    "audit": "audit",
}


def _settings(profile: str) -> Settings:
    """The SHIPPED settings rebound to ``profile``, with the local store kept ephemeral."""
    base = Settings.load(CONFIG_PATH)
    return Settings(
        project_id=base.project_id,
        region=base.region,
        allowed_regions=base.allowed_regions,
        profile=profile,
        max_events=base.max_events,
        logging=base.logging,
        finops=base.finops,
        local=LocalSettings(audit_path=":memory:"),
        adapters=base.adapters,
    )


def _protocol_members(protocol: type) -> set[str]:
    """The attribute names a Protocol declares (methods + properties), no dunders."""
    members = set(getattr(protocol, "__protocol_attrs__", set()))
    if not members:  # pragma: no cover - fallback for older typing internals
        members |= set(get_type_hints(protocol).keys())
    return {m for m in members if not m.startswith("_")}


def _exported_protocols() -> dict[str, type]:
    """Every runtime_checkable Protocol :mod:`observability.ports` exports, by name.

    The ports package also exports the caller-authentication vocabulary and a placeholder
    error, which declare no Protocol because agent-observability binds no identity ADAPTER.
    Filtering on
    ``_is_runtime_protocol`` keeps those out without a hand-written exemption list that would
    need editing every time the vocabulary grows.
    """
    found: dict[str, type] = {}
    for name in ports.__all__:
        obj = getattr(ports, name)
        if isinstance(obj, type) and getattr(obj, "_is_runtime_protocol", False):
            found[name] = obj
    return found


# --------------------------------------------------------------------------- #
# The port set: protocol map <-> the shipped adapter map, both directions
# --------------------------------------------------------------------------- #
def test_protocol_map_and_shipped_adapter_map_name_the_same_ports() -> None:
    bound = set(Settings.load(CONFIG_PATH).adapters)
    declared = set(PORT_PROTOCOLS)

    unmapped = bound - declared
    assert not unmapped, (
        f"ports bound in config/settings.yaml but absent from PORT_PROTOCOLS (so they get NO "
        f"conformance, constructor or profile-coverage enforcement): {sorted(unmapped)}. "
        "Add them to the parity map."
    )
    unbound = declared - bound
    assert not unbound, (
        f"ports in PORT_PROTOCOLS with no binding in config/settings.yaml: {sorted(unbound)}. "
        "Either bind them or drop them; an entry with no adapter overstates what this hexagon "
        "actually covers."
    )


def test_every_exported_protocol_is_a_bound_port() -> None:
    """A Protocol in ``ports/`` that nothing binds is a hexagon edge the service cannot reach."""
    exported = _exported_protocols()
    mapped = set(PORT_PROTOCOLS.values())

    orphans = {name for name, proto in exported.items() if proto not in mapped}
    assert not orphans, (
        f"runtime_checkable Protocols exported by observability.ports with no port binding: "
        f"{sorted(orphans)}. Bind them in config/settings.yaml (and add them to PORT_PROTOCOLS), "
        "or stop exporting an interface no adapter fills."
    )
    foreign = {
        port for port, proto in PORT_PROTOCOLS.items() if proto not in set(exported.values())
    }
    assert not foreign, (
        f"ports mapped to a Protocol that observability.ports does not export: {sorted(foreign)}. "
        "The ports package is the port registry; a look-alike declared elsewhere is how two "
        "copies of one interface drift apart while isinstance stays green."
    )


def test_every_port_is_reachable_through_the_container() -> None:
    assert set(PORT_ACCESSORS) == set(PORT_PROTOCOLS), (
        "PORT_ACCESSORS and PORT_PROTOCOLS must cover the same ports"
    )
    for port_name, attribute in PORT_ACCESSORS.items():
        assert hasattr(Container, attribute), (
            f"port '{port_name}' has a binding but Container exposes no '{attribute}' accessor, "
            "so nothing in the service can obtain it"
        )


# --------------------------------------------------------------------------- #
# The profile set: adapter map <-> the profile registry, both directions
# --------------------------------------------------------------------------- #
def test_every_port_binds_every_runtime_profile() -> None:
    """Every declared port has a binding in every profile ``RUNTIME_PROFILES`` admits.

    The expected set is READ from ``config.RUNTIME_PROFILES`` rather than written out here. A
    literal ``{"local", "gcp", "onprem"}`` would keep passing on the day a fourth profile joins
    the registry with nothing bound to it, and that is exactly the case where an operator selects
    the new profile and the service raises at the first audit write instead of at boot.
    """
    adapters = Settings.load(CONFIG_PATH).adapters
    for port_name in PORT_PROTOCOLS:
        binding = adapters.get(port_name, {})
        missing = set(RUNTIME_PROFILES) - set(binding)
        assert not missing, (
            f"port '{port_name}' has no adapter bound for profile(s) {sorted(missing)}; "
            f"config.RUNTIME_PROFILES admits {sorted(RUNTIME_PROFILES)}"
        )


def test_no_binding_names_a_profile_nothing_may_select() -> None:
    adapters = Settings.load(CONFIG_PATH).adapters
    for port_name, binding in adapters.items():
        stray = set(binding) - set(RUNTIME_PROFILES)
        assert not stray, (
            f"port '{port_name}' binds profile(s) {sorted(stray)} that config.RUNTIME_PROFILES "
            "refuses, so the adapter is dead weight and its coverage is imaginary"
        )


# --------------------------------------------------------------------------- #
# Structural conformance of the SHIPPED bindings, for every profile
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("profile", sorted(RUNTIME_PROFILES))
@pytest.mark.parametrize("port_name", sorted(PORT_PROTOCOLS))
def test_shipped_binding_satisfies_its_protocol(profile: str, port_name: str) -> None:
    """Every family, ``gcp`` included, constructs offline: its SDK imports are lazy by contract.

    Sweeping all three rather than only the SDK-free pair is deliberate here. agent-observability is
    the audit
    store every other system writes to, so a managed binding that cannot even be constructed is
    a deployment that loses the evidence trail, and the lazy-import discipline is what makes the
    check possible without credentials.
    """
    settings = _settings(profile)
    protocol = PORT_PROTOCOLS[port_name]
    dotted = settings.adapters.get(port_name, {}).get(profile, "")
    assert dotted, (
        f"port '{port_name}' has no '{profile}' binding, so there is no adapter to hold to "
        f"{protocol.__name__}"
    )

    # Import + construct with only Settings (the adapter convention).
    adapter = _load(dotted, settings)

    assert isinstance(adapter, protocol), (
        f"{dotted} does not structurally satisfy {protocol.__name__}"
    )

    # Every declared Protocol member exists. Looked up on the CLASS via the MRO, not the
    # instance: the fail-fast onprem placeholder raises when invoked, so ``hasattr`` on a
    # property would wrongly report it missing.
    declared = set().union(*(vars(klass) for klass in type(adapter).__mro__))
    for member in _protocol_members(protocol):
        assert member in declared, (
            f"{dotted} is missing port method '{member}' of {protocol.__name__}"
        )


def test_all_mapped_protocols_are_runtime_checkable() -> None:
    """``isinstance`` above is meaningless against a Protocol that is not runtime_checkable."""
    for port_name, protocol in PORT_PROTOCOLS.items():
        assert issubclass(protocol, Protocol)  # type: ignore[arg-type]
        assert getattr(protocol, "_is_runtime_protocol", False), (
            f"{protocol.__name__} (port '{port_name}') must be @runtime_checkable"
        )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
