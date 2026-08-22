"""Hash-chain primitives for the local WORM stand-in (practice C9).

The chain convention here is not merely *like* the commons one, it **is** the commons one:
this module binds :mod:`hex_service_kit.audit`'s canonical-JSON encoder, its link function
(``entry_hash = SHA-256(prev_hash || "\\n" || event_json)``) and its genesis marker under
local names instead of restating the algorithm. The catalog therefore holds exactly one
implementation of the link, and a trail exported here re-verifies with the commons reader
byte for byte (systemic finding 1: adopt the commons, never copy it).

The adapter that uses these primitives (:mod:`.audit`) *extends*
:class:`hex_service_kit.audit.HashChainedAuditLog` rather than re-implementing it. Its two
genuine deltas over the commons store are the **retention watermark** (the ``local`` profile
is a windowed read-back buffer, ``OBSERVABILITY_MAX_EVENTS``, oldest pruned first, so the
chain is anchored at the last pruned entry instead of at genesis) and the idempotency ledger
(``event_id`` / ``idempotency_key`` unique indexes) that the commons store has no notion of.
"""

from __future__ import annotations

from typing import Any

# Private by name but deliberately bound rather than copied: re-declaring these would fork
# the catalog's chain convention into two implementations that can silently diverge.
from hex_service_kit.audit import _GENESIS, _canonical, _entry_hash

GENESIS: str = _GENESIS  # prev_hash of the very first chained record (commons convention)


def canonical(payload: Any) -> str:
    """The one canonical JSON encoding hashed, stored, exported and re-verified."""
    return _canonical(payload)


def entry_hash(prev_hash: str, event_json: str) -> str:
    """``SHA-256(prev_hash || "\\n" || event_json)`` — the commons chain link."""
    return _entry_hash(prev_hash, event_json)
