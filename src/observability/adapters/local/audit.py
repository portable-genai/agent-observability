"""Local audit adapter (``AuditSinkPort``) — append-only, hash-chained SQLite WORM stand-in.

The ``local`` profile's offline stand-in for the **Cloud Logging locked WORM bucket**: an
append-only SQLite table (or an in-memory table for ``:memory:``) that records already
redacted audit events and supports read-back, newest first, filtered by actor / action.
Append-only is enforced *in the store* by SQLite triggers, not merely by the absence of an
update method (rule R2). It is SDK-free, deterministic and seedable so the service runs and
the test suite passes with **no Google Cloud SDK installed**.

Tamper evidence (practice C9)
-----------------------------
This adapter **extends** :class:`hex_service_kit.audit.HashChainedAuditLog` (the catalog's
shared WORM primitive) rather than restating it: the connection, the chain columns, the
UPDATE trigger, the anchor file and the JSON Lines export all come from the commons. The
deltas this profile adds are the queryable/idempotency columns and the retention watermark
described below. Every record is cryptographically chained to its predecessor using the
commons link (``entry_hash = SHA-256(prev_hash || "\\n" || event_json)`` over the exact
stored canonical JSON; see :mod:`._chain`), and the trail exports to / restores from the
commons JSON Lines format with every link re-verified. That export leads with the commons
anchor header, so the witness travels with the data instead of staying behind with the
source store.

The trust boundary these claims are made against: **an actor who can write the SQLite file
but cannot write the anchor file.** Both lists below are asserted, tamper by tamper, in
``tests/test_audit_chain.py``, including the ones that say "not detected".

**Detected** by :meth:`LocalAppendOnlyAuditAdapter.verify_chain`, with no anchor needed:

* an in-place edit of any stored field (``entry_hash`` mismatch);
* an interior deletion or a reordering (``prev_hash`` no longer extends the chain);
* a row carrying no chain hashes. A direct ``INSERT ... (prev_hash, entry_hash) VALUES
  (NULL, NULL)`` trips no trigger (they block UPDATE and DELETE, not INSERT) and leaves the
  chain around it intact, so the count lands in ``legacy`` and the report is ``ok=False``:
  an unverified row is never reported as verified history. Rows written before chaining
  existed answer the same way, because nothing in the store tells the two apart.

**Detected additionally when ``anchor_path`` is configured** (and the actor cannot write it):

* a truncated tail and a wholesale re-chained rewrite (the anchored head no longer matches);
* a **prefix deletion dressed up as a retention prune**: rows erased with the prune watermark
  advanced to match, so the surviving chain is self-consistent. The anchor binds the watermark
  as well as the head, so the forged prune state is a mismatch;
* a **missing** anchor file, and equally a **degraded** one whose watermark keys were deleted
  to skip half the check. Both answer the same way rather than one being loud and the other
  silent;
* **laundering by ordinary traffic afterwards.** Every one of the above survives the next
  append: :meth:`record` fails closed with ``AuditChainError`` when the store no longer
  matches the anchor, instead of re-anchoring the store's current contents. Before that, the
  anchor was last-write-wins, so a single ordinary request after a tamper restored "chain
  intact" and detection was a millisecond race rather than a property. The cost is deliberate:
  a tampered store stops accepting audit records until an operator intervenes.
* **laundering through the restore command.** :meth:`import_jsonl` is the only other path
  that establishes what the verifier trusts, and it refuses while the configured anchor file
  exists. Otherwise restoring a deliberately shortened export into a fresh store path, with
  the anchor still pointed at the live witness, overwrote that witness with no check and no
  confirmation, i.e. a ``reanchor`` without ``--confirm`` wearing an operator's clothes.
* **an export shortened in transit, at either end.** The anchor header on line 1 of an export
  is checked against the records that arrive with it, so dropping the newest lines (the tail)
  or the oldest lines of a window (which the restore would otherwise adopt as a later
  retention watermark) is refused rather than restored. Both shortenings leave a chain that
  links perfectly, so nothing inside the file can expose either; the exporter's committed
  head and watermark are what do. A trail restored from a **pre-anchor** export carries no
  such witness, and :meth:`verify_chain` reports it unanchored rather than intact until an
  operator calls :meth:`reanchor`.

There are exactly three writers of the anchor file -- :meth:`record`, :meth:`import_jsonl`
and :meth:`reanchor` -- and the first two now refuse rather than write over a witness that
disagrees; the third is the deliberate operator action. Nothing else in the tree (the CLI,
the API, the constructor, the prune) touches it.

**Not detected**, precisely:

* a rewrite by an actor who holds write access to BOTH the store and the anchor. The chain
  carries no secret, so it can be recomputed end to end. This covers the degraded / deleted
  anchor cases above once the same actor also calls :meth:`reanchor`: re-anchoring asserts
  nothing about the past, it only re-witnesses the store as it now stands, which is why it is
  an explicit operator action and never happens on the append path;
* with **no anchor configured** (a ``:memory:`` store, or an explicitly blank
  ``anchor_path``), a shorter-but-valid tail truncation and the prune-state rewrite above,
  since nothing outside the store then witnesses either the head or the watermark. A clean
  :meth:`verify_chain` says so in its ``detail`` instead of the bare "chain intact" a
  witnessed store gets, because whether these classes are detectable AT ALL is a deployment
  choice and the operator reading "OK" has to know which OK this is;
* **who** tampered, or when. There is no signature and no timestamp authority here: the trail
  proves that content changed, not who changed it;
* anything at all on the optional Firestore-emulator branch, which is unchained; verify,
  export and restore refuse to run against it rather than pretend otherwise.

Keep the anchor on a different volume or under different credentials. The managed ``gcp``
profile does not rely on any of this: the locked Cloud Logging bucket provides
non-rewritability itself.

Retention pruning stays verifiable: ``max_events`` prunes oldest rows first, and the prune
records a **watermark** (the seq + entry_hash of the last pruned record) that the retained
window must chain onto. A deletion outside that recorded prune is blocked by the DELETE
trigger and, if forced at the file level, breaks the chain at the next verify. The watermark
itself lives in an ordinary table that a file-level attacker can rewrite, which is precisely
why every anchor write carries it: a forged prune state no longer matches the anchor. The
hash is the load-bearing half and the seq is provenance: a window restored from an export
adopts the hash with no seq to adopt alongside it, and a tamperer can null either column, so
both cases are reported rather than crashed on (raising ``TypeError`` there answers a tamper
with a traceback and no report at all).

Records are serialised with the domain :func:`to_jsonable` so a stored event round-trips
through JSON exactly like the managed Cloud Logging sink writes it. ``max_events`` caps
retained rows for read-back demos (oldest pruned first), matching the managed read-back
window in spirit.

Optional higher-fidelity branch: when ``FIRESTORE_EMULATOR_HOST`` is set AND
``google-cloud-firestore`` (installed alongside the ``[gcp]`` extra) imports, the same
append-only records are written to / read from the local Firestore emulator instead. The
google client is imported lazily inside that branch only, so the default SQLite path never
imports a google-cloud package. The emulator branch is best-effort: it appends without the
SQLite path's ``max_events`` pruning, so the emulator-backed store grows unbounded. There
is no Cloud Logging emulator, hence SQLite is the default WORM stand-in.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from hex_service_kit import EXPORT_FORMAT, AuditChainError, ChainReport
from hex_service_kit.audit import HashChainedAuditLog, scan_chain_rows

from ...config import Settings
from ...errors import IdempotencyConflict
from ...models import AuditEvent, Citation, Decision
from ...serialization import to_jsonable
from ._chain import GENESIS, canonical, entry_hash
from ._emulator import firestore_emulator_active, firestore_emulator_host
from ._seed import SEED_EVENTS

_DEFAULT_DB_DIR = Path.home() / ".observability"
_DEFAULT_AUDIT_PATH = _DEFAULT_DB_DIR / "audit.db"


class LocalAppendOnlyAuditAdapter(HashChainedAuditLog):
    """Append-only audit store: records already-redacted events, read-back supported.

    Extends the commons :class:`hex_service_kit.audit.HashChainedAuditLog`: the connection,
    the ``audit_log`` table, the chain columns, the UPDATE trigger, the external anchor and
    the JSON Lines export come from there. This subclass adds only what the ``local``
    profile genuinely needs on top: queryable ``actor`` / ``action`` columns, the
    idempotency ledger, and the retention watermark with its prune-gated DELETE trigger.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._max_events = max(1, settings.max_events)

        # Optional emulator opt-in (lazy google import lives behind this flag only).
        self._use_emulator = firestore_emulator_active()
        self._fs: Any | None = None
        self._fs_collection = "agent_observability_audit"

        path = settings.local.audit_path or str(_DEFAULT_AUDIT_PATH)
        # The commons constructor opens the connection (check_same_thread=False + a lock,
        # because the FastAPI app shares one adapter across threads), creates the chained
        # table and the WORM triggers, and records the anchor path.
        super().__init__(path, anchor_path=self._resolve_anchor_path(settings, path))
        table_info = self._conn.execute("PRAGMA table_info(audit_log)").fetchall()
        columns = {str(row["name"]) for row in table_info}
        # The commons table carries only (seq, event_json, prev_hash, entry_hash). These are
        # this profile's additions: read-back filters plus the idempotency ledger. A store
        # created before chaining existed lacks prev_hash / entry_hash; the commons
        # constructor adds those, and its old rows keep NULL hashes: verify_chain() counts
        # them in 'legacy' and reports the trail as NOT intact, because an unhashed row is
        # indistinguishable from one a direct INSERT fabricated.
        for name in (
            "action",
            "actor",
            "decision",
            "timestamp",
            "event_id",
            "idempotency_key",
            "payload_digest",
        ):
            if name not in columns:
                self._conn.execute(f"ALTER TABLE audit_log ADD COLUMN {name} TEXT")
        # Retention watermark: the last record removed by a capacity prune. The retained
        # window must chain onto it, so pruning cannot be used to hide a deletion.
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_chain_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                pruned_seq INTEGER,
                pruned_hash TEXT,
                prune_open INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self._conn.execute(
            "INSERT OR IGNORE INTO audit_chain_state (id, pruned_seq, pruned_hash, prune_open) "
            "VALUES (1, NULL, NULL, 0)"
        )
        # WORM in the store, not just by convention. The commons UPDATE trigger stands as
        # created; its unconditional DELETE trigger is replaced by a gated one, because this
        # profile is a windowed buffer that must be able to prune its own oldest rows. The
        # gate opens only inside _prune_to_capacity, which records the watermark first.
        self._conn.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
        self._conn.execute(
            "CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log "
            "WHEN (SELECT prune_open FROM audit_chain_state WHERE id = 1) = 0 "
            "BEGIN SELECT RAISE(ABORT, "
            "'audit_log is append-only (WORM): DELETE blocked outside a recorded retention "
            "prune'); END"
        )
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_event_id "
            "ON audit_log(event_id) WHERE event_id IS NOT NULL AND event_id != ''"
        )
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_idempotency_key "
            "ON audit_log(idempotency_key) "
            "WHERE idempotency_key IS NOT NULL AND idempotency_key != ''"
        )
        self._conn.commit()

    # ------------------------------------------------------------------ #
    # Seeding (deterministic corpus for the CLI smoke run + tests)
    # ------------------------------------------------------------------ #
    def seed(self, events: tuple[AuditEvent, ...] | None = None) -> int:
        """Append the built-in (or supplied) sample events. Returns the count appended."""
        batch = SEED_EVENTS if events is None else events
        for event in batch:
            self.record(event)
        return len(batch)

    def count(self) -> int:
        """Total rows currently retained in the default SQLite store (CLI ``seed`` output).

        Diagnostics only: this always reads the SQLite table, so under the optional
        Firestore-emulator branch (best-effort, no pruning) it reports the local table's
        count rather than the emulator's.
        """
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()
        return int(row["n"])

    # ------------------------------------------------------------------ #
    # AuditSinkPort.record
    # ------------------------------------------------------------------ #
    def record(self, event: object) -> None:
        """Append one immutable, already-redacted audit record (no update / delete).

        Typed as ``object`` to stay substitutable for the commons base class; the ``local``
        store persists this repo's :class:`AuditEvent` shape (queryable actor/action columns
        plus the idempotency ledger), so anything else is a programming error.
        """
        if not isinstance(event, AuditEvent):
            raise TypeError(f"local audit store records AuditEvent, got {type(event).__name__}")
        event_id = event.event_id.strip() or f"audit-{uuid4().hex}"
        normalized = replace(event, event_id=event_id)
        encoded = json.dumps(to_jsonable(normalized), sort_keys=True, separators=(",", ":"))
        digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        self.record_once(
            normalized,
            idempotency_key=f"event:{event_id}",
            payload_digest=digest,
        )

    def record_once(
        self,
        event: AuditEvent,
        *,
        idempotency_key: str,
        payload_digest: str,
    ) -> str:
        """Append once; identical retries return the original event ID."""
        event_id = event.event_id.strip()
        key = idempotency_key.strip()
        digest = payload_digest.strip()
        if not event_id or not key or not digest:
            raise ValueError("event_id, idempotency_key, and payload_digest are required")
        if self._use_emulator:
            return self._record_once_emulator(event, key, digest)
        payload = to_jsonable(event)
        with self._lock:
            existing = self._conn.execute(
                "SELECT event_id, payload_digest FROM audit_log "
                "WHERE idempotency_key = ? OR event_id = ? LIMIT 1",
                (key, event_id),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["event_id"]) == event_id
                    and str(existing["payload_digest"]) == digest
                ):
                    return event_id
                raise IdempotencyConflict(
                    "idempotency key or event ID was reused for different audit content"
                )
            # Fail closed rather than re-anchor a store that has diverged from its witness:
            # without this, one ordinary append after a tamper rewrote the anchor from the
            # forged state and verification went green again (see _assert_anchor_continuity).
            self._assert_anchor_continuity()
            event_json = canonical(payload)
            prev_hash = self._head_hash()
            self._conn.execute(
                "INSERT INTO audit_log "
                "(action, actor, decision, timestamp, event_id, idempotency_key, "
                "payload_digest, event_json, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.action,
                    event.actor,
                    event.decision.value,
                    to_jsonable(event.timestamp),
                    event_id,
                    key,
                    digest,
                    event_json,
                    prev_hash,
                    entry_hash(prev_hash, event_json),
                ),
            )
            # Prune oldest rows beyond capacity (read-back demo bound; the managed sink
            # retains everything for ~7y in the locked bucket). The prune is RECORDED as a
            # watermark first, so the retained window still chains onto a known hash.
            self._prune_to_capacity()
            self._conn.commit()
            self._write_anchor()
        return event_id

    # ------------------------------------------------------------------ #
    # Hash chain: head, retention watermark, external anchor
    # ------------------------------------------------------------------ #
    def _head_hash(self) -> str:
        """Current chain head: the newest chained entry_hash, else the pruned watermark."""
        row = self._conn.execute(
            "SELECT entry_hash FROM audit_log WHERE entry_hash IS NOT NULL "
            "ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is not None:
            return str(row["entry_hash"])
        return self._watermark()[1]

    def _watermark(self) -> tuple[int | None, str]:
        """``(seq, entry_hash)`` of the last pruned record; ``(None, GENESIS)`` if none.

        The hash is what the retained window must chain onto; the seq is provenance only, and
        it is legitimately unknown when the window was restored from an export rather than
        pruned here (:meth:`_restore_line` adopts the exported window's first ``prev_hash``
        and has no seq to adopt with it). The two columns are also independently writable by
        anyone with file access. So a hash without a seq is a state to REPORT, never one to
        crash on: an unguarded ``int(None)`` turns both a legitimate restored window and a
        prefix-deletion forgery into an uncaught ``TypeError`` out of verify and out of the
        next append, i.e. no answer at all where an answer is the whole point.
        """
        row = self._conn.execute(
            "SELECT pruned_seq, pruned_hash FROM audit_chain_state WHERE id = 1"
        ).fetchone()
        if row is None or row["pruned_hash"] is None:
            return None, GENESIS
        pruned_seq = row["pruned_seq"]
        return (int(pruned_seq) if pruned_seq is not None else None), str(row["pruned_hash"])

    def _prune_to_capacity(self) -> None:
        """Drop oldest rows beyond ``max_events``, recording the new retention watermark."""
        cutoff_row = self._conn.execute(
            "SELECT MAX(seq) - ? AS cutoff FROM audit_log", (self._max_events,)
        ).fetchone()
        cutoff = cutoff_row["cutoff"] if cutoff_row is not None else None
        if cutoff is None:
            return
        last = self._conn.execute(
            "SELECT seq, entry_hash FROM audit_log WHERE seq <= ? ORDER BY seq DESC LIMIT 1",
            (cutoff,),
        ).fetchone()
        if last is None:
            return
        self._conn.execute(
            "UPDATE audit_chain_state SET pruned_seq = ?, pruned_hash = ?, prune_open = 1 "
            "WHERE id = 1",
            (int(last["seq"]), last["entry_hash"]),
        )
        try:
            self._conn.execute("DELETE FROM audit_log WHERE seq <= ?", (cutoff,))
        finally:
            self._conn.execute("UPDATE audit_chain_state SET prune_open = 0 WHERE id = 1")

    def _anchor_payload(self) -> dict[str, Any] | None:
        """The commons ``{"seq", "entry_hash"}`` anchor plus this profile's prune watermark.

        The anchor turns "a valid chain" into "the SAME chain": keep it on a different
        volume or under different credentials than the store, otherwise an actor who can
        rewrite the store can rewrite the anchor with it.

        The watermark travels with the head because it is the only other input
        :meth:`verify_chain` trusts, and it lives in an ordinary in-store table. Without
        this binding, an actor with file access could erase the oldest N records and move
        the watermark to the last erased record: a self-consistent chain that verified
        clean. Anchoring the watermark makes that forgery a mismatch. The extra keys are
        additive, so a commons reader of the ``{"seq", "entry_hash"}`` shape still works.
        """
        payload = super()._anchor_payload()
        if payload is None:
            return None
        pruned_seq, pruned_hash = self._watermark()
        payload["pruned_seq"] = pruned_seq
        payload["pruned_hash"] = pruned_hash
        return payload

    def _anchor_mismatch(self, anchor: dict[str, Any]) -> str:
        """Cross-check the watermark as well as the head, and demand both be witnessed.

        An anchor carrying no watermark keys is treated as a disagreement, not as licence to
        skip half the check. Such an anchor is either pre-binding (written before the
        watermark travelled with the head) or downgraded by an actor who deleted exactly
        those two keys to buy back a clean verify over a forged prune. Nothing in the file
        distinguishes the two, so both answer the same way, and both are cleared the same
        deliberate way: verify the store out of band, then :meth:`reanchor`.
        """
        pruned_seq, pruned_hash = self._watermark()
        if "pruned_hash" not in anchor or "pruned_seq" not in anchor:
            return (
                "external anchor carries no retention watermark: the watermark half of the "
                f"cross-check cannot be performed ({self._anchor_path}); the anchor predates "
                "the binding or has been downgraded. Re-establish it with reanchor()"
            )
        if (
            str(anchor.get("pruned_hash") or "") != pruned_hash
            or anchor.get("pruned_seq") != pruned_seq
        ):
            return (
                "retention watermark does not match the external anchor "
                f"(anchored pruned seq {anchor.get('pruned_seq')}, store says {pruned_seq}): "
                "records deleted outside a recorded prune, with the prune state rewritten "
                "to match"
            )
        return super()._anchor_mismatch(anchor)

    @staticmethod
    def _resolve_anchor_path(settings: Settings, store_path: str) -> str:
        """Explicit ``local.anchor_path`` wins; otherwise derive one beside a file store.

        An in-memory (``:memory:``) store has no anchor: there is no file to truncate, and
        the process that holds the store also holds the anchor, which would prove nothing.
        """
        configured = settings.local.anchor_path.strip()
        if configured:
            return configured
        if store_path in (":memory:", "") or store_path.startswith("file:"):
            return ""
        return f"{store_path}.anchor.json"

    # ------------------------------------------------------------------ #
    # AuditSinkPort.read_recent
    # ------------------------------------------------------------------ #
    def get(self, event_id: str) -> AuditEvent | None:
        """Resolve one event by ID."""
        if self._use_emulator:
            docs = self._firestore().collection(self._fs_collection).stream()
            for doc in docs:
                payload = doc.to_dict() or {}
                if payload.get("event_id") == event_id:
                    return _event_from_payload(payload)
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT event_json FROM audit_log WHERE event_id = ? LIMIT 1",
                (event_id,),
            ).fetchone()
        return _event_from_payload(json.loads(row["event_json"])) if row is not None else None

    def read_recent(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        limit: int = 50,
    ) -> list[AuditEvent]:
        """Return up to ``limit`` recent events (newest first), filtered by actor / action."""
        if self._use_emulator:
            return self._read_recent_emulator(actor=actor, action=action, limit=limit)
        bound = max(1, min(limit, self._max_events))
        sql = "SELECT event_json FROM audit_log"
        clauses: list[str] = []
        params: list[Any] = []
        if actor is not None:
            clauses.append("actor = ?")
            params.append(actor)
        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq DESC LIMIT ?"
        params.append(bound)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_event_from_payload(json.loads(row["event_json"])) for row in rows]

    # ------------------------------------------------------------------ #
    # Tamper evidence: verify / export / restore (practice C9)
    # ------------------------------------------------------------------ #
    def _require_sqlite_chain(self, operation: str) -> None:
        if self._use_emulator:
            raise AuditChainError(
                f"'{operation}' operates on the chained SQLite WORM store; the optional "
                "Firestore-emulator branch is an unchained best-effort fidelity aid"
            )

    def verify_chain(self) -> ChainReport:
        """Re-derive every hash from the stored bytes and confirm the chain still links.

        Returns a :class:`hex_service_kit.ChainReport`. See the module docstring for the
        exact tamper classes this does and does not detect.
        """
        self._require_sqlite_chain("verify")
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, event_json, prev_hash, entry_hash FROM audit_log ORDER BY seq ASC"
            ).fetchall()
            pruned_seq, anchored_watermark = self._watermark()
            # The row walk is the commons rule (including "a row with no hashes is
            # unverifiable, so the trail is not intact"); the only local delta is where the
            # walk starts, because a windowed store is rooted at its retention watermark
            # rather than at genesis.
            scan = scan_chain_rows(rows, expected_prev=anchored_watermark)
            # A truncated tail, and equally a prefix deletion recorded as a prune, leave a
            # perfectly valid shorter chain. Only the external anchor exposes either, so it
            # is cross-checked on both the head and the watermark the chain is rooted at.
            # A trail restored from a pre-anchor export is asked first, because there the
            # answer is not "the witness disagrees" but "no witness ever crossed with it".
            problem = (
                ""
                if not scan.ok
                else (self._unanchored_restore_problem() or self._anchor_disagreement())
            )
        if not scan.ok:
            detail = scan.detail
            if (
                pruned_seq is not None
                and scan.chained == 0
                and "does not extend the chain" in detail
            ):
                detail += f" (retained window must chain onto pruned seq {pruned_seq})"
            return ChainReport(
                ok=False,
                entries=len(rows),
                chained=scan.chained,
                legacy=scan.legacy,
                first_bad_seq=scan.first_bad_seq,
                detail=detail,
            )
        if problem:
            return ChainReport(
                ok=False,
                entries=len(rows),
                chained=scan.chained,
                legacy=scan.legacy,
                first_bad_seq=None,
                detail=problem,
            )
        # Say which of the two "intact"s this is. Whether a truncated tail or a forged prune
        # is detectable AT ALL is a deployment choice (is an anchor configured, and is it
        # somewhere this store's writer cannot reach), so an unwitnessed store must not print
        # the same sentence as a witnessed one: "OK" would mean less than the reader thinks.
        return ChainReport(
            ok=True,
            entries=len(rows),
            chained=scan.chained,
            legacy=scan.legacy,
            detail=(
                "chain intact"
                if self._anchor_path
                else (
                    "chain intact, but no external anchor is configured: a truncated tail "
                    "and a prefix deletion recorded as a retention prune are undetectable "
                    "here (set OBSERVABILITY_LOCAL_ANCHOR, on a different volume)"
                )
            ),
        )

    def export_jsonl(self, path: str | Path) -> int:
        """Export the retained trail as JSON Lines: anchor header, then one record per line.

        The writer itself is the commons one, so any consumer can re-verify integrity
        without this codebase and the format cannot drift from the catalog's. Line 1 is the
        anchor header (``{"anchor": {...}, "format"}``) and every later line is a record
        (``{"seq", "prev_hash", "entry_hash", "event"}``). The anchor this profile writes
        carries the retention watermark alongside the head, so a window export states which
        pruned record it chains onto rather than leaving the recipient to take the first
        ``prev_hash`` on trust. Returns the number of RECORDS written, header excluded.
        """
        self._require_sqlite_chain("export")
        return super().export_jsonl(path)

    def import_jsonl(self, path: str | Path) -> int:
        """Restore an exported trail into this (empty) store, re-verifying every link.

        Refuses a non-empty target (append-only stores never merge) and any record whose
        hashes do not check out. A window that was pruned upstream starts at its retention
        watermark rather than at genesis: that first ``prev_hash`` is adopted as the
        watermark, so the restore proves continuity of what it received, not that nothing
        preceded it. Returns the count restored.

        It also refuses when the configured anchor file already exists, because finishing the
        restore would rewrite that anchor from the trail just imported. This is the SECOND
        path that re-establishes what :meth:`verify_chain` trusts, and doing so with no check
        and no confirmation while :meth:`reanchor` demands an explicit one leaves a hole:
        restore a deliberately shortened export into a fresh store path with the anchor env var
        still pointing at the live witness, and the witness of everything dropped is
        overwritten.
        Give the restored store its own anchor path, or re-establish one deliberately after.

        The export's own anchor header is the witness the arriving trail is checked against,
        which is what makes a truncated export refusable at all: drop the newest lines and
        the shorter chain still links perfectly, so nothing inside the file objects. Both
        halves of this profile's anchor are checked, for the same reason :meth:`verify_chain`
        checks both -- the head catches a dropped tail, and the watermark catches the
        mirror-image forgery of dropping the OLDEST lines so the window silently re-roots
        itself further along. Neither is derived from the payload being imported, which would
        agree with that payload by construction and witness only itself.

        What is then written to this store's own anchor file is re-derived locally, because a
        restore renumbers: ``seq`` is store-local and the watermark's ``pruned_seq`` with it,
        while the hashes chain over event content and survive the move. So the travelled
        anchor is the authority for ACCEPTING the trail, and the local anchor records the
        accepted trail under this store's numbering.

        An export written before the header existed still restores, and :meth:`verify_chain`
        then reports the trail as unanchored rather than intact until an operator calls
        :meth:`reanchor`: nothing in such a file witnesses its own tail.

        A refusal restores nothing at all -- the half-walked rows are rolled back -- so there
        is no partial trail left readable through :meth:`read_recent` or re-exportable.
        """
        self._require_sqlite_chain("restore")
        with self._lock:
            count = int(self._conn.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()["n"])
            if count:
                raise AuditChainError(
                    "refusing to restore into a non-empty audit store (append-only); "
                    "point OBSERVABILITY_LOCAL_AUDIT at a fresh path"
                )
            if self._anchor_path and Path(self._anchor_path).exists():
                raise AuditChainError(
                    f"refusing to restore: the configured external anchor "
                    f"({self._anchor_path}) already witnesses a store, and completing the "
                    "restore would rewrite it from the trail being imported. Point "
                    "OBSERVABILITY_LOCAL_ANCHOR at a fresh path for the restored store, or "
                    "re-establish the witness deliberately afterwards (audit reanchor "
                    "--confirm)"
                )
            try:
                anchor, imported = self._restore_lines(Path(path).read_text(encoding="utf-8"))
            except Exception:
                self._conn.rollback()  # refusing means nothing lands, not "most of it lands"
                raise
            self._conn.commit()
            self._unanchored_restore = anchor is None
            self._write_anchor()
        return imported

    def _restore_lines(self, text: str) -> tuple[dict[str, Any] | None, int]:
        """Walk one export, inserting the records; return its anchor (if any) and the count.

        The caller holds the lock and owns the commit/rollback, so every way out of here that
        raises leaves the inserts uncommitted.
        """
        anchor: dict[str, Any] | None = None
        expected_prev: str | None = None
        imported = 0
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise AuditChainError(f"line {lineno}: export line is not a JSON object")
            if "anchor" in entry:
                if anchor is not None or imported:
                    raise AuditChainError(
                        f"line {lineno}: a second anchor header, or an anchor header after "
                        "the records. The export carries exactly one, on its first line"
                    )
                anchor = self._read_anchor_header(entry, lineno)
                continue
            imported += 1
            expected_prev = self._restore_line(lineno, entry, expected_prev)
        if anchor is not None:
            self._assert_export_anchor(anchor, head=expected_prev or GENESIS)
        return anchor, imported

    @staticmethod
    def _read_anchor_header(entry: dict[str, Any], lineno: int) -> dict[str, Any]:
        """Read the anchor out of an export's header line, refusing a shape it cannot check."""
        stated = entry.get("format")
        if stated != EXPORT_FORMAT:
            raise AuditChainError(
                f"line {lineno}: export format {stated!r} is not {EXPORT_FORMAT!r}, so its "
                "anchor cannot be interpreted; restore it with the version that wrote it"
            )
        anchor = entry.get("anchor")
        if not isinstance(anchor, dict) or not isinstance(anchor.get("entry_hash"), str):
            raise AuditChainError(
                f"line {lineno}: anchor header carries no readable chain head "
                '(expected {"anchor": {"seq": N, "entry_hash": "..."}})'
            )
        return anchor

    def _assert_export_anchor(self, anchor: dict[str, Any], *, head: str) -> None:
        """Check the restored records against the head and watermark that travelled with them.

        The watermark half is not decoration. Dropping the OLDEST lines of a window export is
        the transit twin of the forged retention prune :meth:`verify_chain` already refuses:
        the restore adopts whatever first ``prev_hash`` it is handed as the watermark, so the
        shortened window re-roots itself and verifies clean. Only the exporter's own
        ``pruned_hash`` says which record the window was really supposed to chain onto.
        """
        anchored_head = str(anchor.get("entry_hash") or "")
        if anchored_head != head:
            raise AuditChainError(
                f"the restored records end at {head or '(empty trail)'}, but this export is "
                f"anchored to seq {anchor.get('seq')} / "
                f"{anchored_head or '(empty trail)'}: records are missing from the tail "
                "(the export was truncated or rewritten in transit)"
            )
        if "pruned_hash" not in anchor:
            raise AuditChainError(
                "the export's anchor header carries no retention watermark: the watermark "
                "half of the cross-check cannot be performed, so a window that re-roots "
                "itself further along cannot be told from the window that was sent. The "
                "header predates the binding or has been downgraded in transit"
            )
        _, restored_watermark = self._watermark()
        anchored_watermark = str(anchor.get("pruned_hash") or "")
        if anchored_watermark != restored_watermark:
            raise AuditChainError(
                f"the restored window chains onto {restored_watermark or '(genesis)'}, but "
                f"this export is anchored onto {anchored_watermark or '(genesis)'}: records "
                "are missing from the head of the window (the export was truncated at its "
                "oldest end, and the restore would have adopted the shortened root)"
            )

    def _restore_line(self, lineno: int, entry: dict[str, Any], expected_prev: str | None) -> str:
        event = entry.get("event") or {}
        prev_hash, stored_hash = entry.get("prev_hash"), entry.get("entry_hash")
        if prev_hash is None or stored_hash is None:
            raise AuditChainError(
                f"line {lineno}: record has no chain hashes (pre-chaining legacy export) "
                "and cannot be restored verifiably"
            )
        if expected_prev is None and prev_hash != GENESIS:
            # A restored retention window: adopt its starting link as the watermark.
            self._conn.execute(
                "UPDATE audit_chain_state SET pruned_seq = ?, pruned_hash = ? WHERE id = 1",
                (None, str(prev_hash)),
            )
        elif prev_hash != (GENESIS if expected_prev is None else expected_prev):
            raise AuditChainError(
                f"line {lineno}: prev_hash does not extend the chain (records missing or reordered)"
            )
        event_json = canonical(event)
        if entry_hash(str(prev_hash), event_json) != stored_hash:
            raise AuditChainError(f"line {lineno}: entry_hash mismatch (record altered in transit)")
        self._conn.execute(
            "INSERT INTO audit_log "
            "(action, actor, decision, timestamp, event_id, idempotency_key, "
            "payload_digest, event_json, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(event.get("action", "")),
                str(event.get("actor", "")),
                str(event.get("decision", "")),
                str(event.get("timestamp", "")),
                str(event.get("event_id", "")),
                f"restore:{event.get('event_id', lineno)}",
                "sha256:"
                + hashlib.sha256(
                    json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
                event_json,
                str(prev_hash),
                str(stored_hash),
            ),
        )
        return str(stored_hash)

    # ------------------------------------------------------------------ #
    # Optional Firestore-emulator branch (lazy google import, opt-in only)
    # ------------------------------------------------------------------ #
    def _firestore(self) -> Any:
        if self._fs is not None:
            return self._fs
        from google.cloud import firestore  # lazy: only on the emulator opt-in branch

        # The emulator host is taken from FIRESTORE_EMULATOR_HOST by the client library.
        _ = firestore_emulator_host()
        self._fs = firestore.Client(project=self._settings.project_id)
        return self._fs

    def _record_once_emulator(
        self,
        event: AuditEvent,
        idempotency_key: str,
        payload_digest: str,
    ) -> str:
        payload = to_jsonable(event)
        payload["_seq"] = to_jsonable(event.timestamp)
        payload["_idempotency_key"] = idempotency_key
        payload["_payload_digest"] = payload_digest
        doc_id = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        ref = self._firestore().collection(self._fs_collection).document(doc_id)
        existing = ref.get()
        if getattr(existing, "exists", False):
            stored = existing.to_dict() or {}
            if (
                stored.get("event_id") == event.event_id
                and stored.get("_payload_digest") == payload_digest
            ):
                return event.event_id
            raise IdempotencyConflict(
                "idempotency key or event ID was reused for different audit content"
            )
        ref.create(payload)
        return event.event_id

    def _read_recent_emulator(
        self,
        *,
        actor: str | None,
        action: str | None,
        limit: int,
    ) -> list[AuditEvent]:
        bound = max(1, min(limit, self._max_events))
        col = self._firestore().collection(self._fs_collection)
        docs = list(col.stream())
        events = [_event_from_payload(d.to_dict() or {}) for d in docs]
        events.sort(key=lambda e: e.timestamp, reverse=True)
        out: list[AuditEvent] = []
        for event in events:
            if actor is not None and event.actor != actor:
                continue
            if action is not None and event.action != action:
                continue
            out.append(event)
            if len(out) >= bound:
                break
        return out


# --------------------------------------------------------------------------- #
# Deserialisation (read-back) — payload dict -> AuditEvent
# --------------------------------------------------------------------------- #
def _citation_from_dict(raw: dict[str, Any]) -> Citation:
    page = raw.get("page")
    score = raw.get("score")
    return Citation(
        source_id=str(raw.get("source_id", "")),
        regulator=str(raw.get("regulator", "")),
        jurisdiction=str(raw.get("jurisdiction", "")),
        title=str(raw.get("title", "")),
        url=str(raw.get("url", "")),
        version=str(raw.get("version", "unknown")),
        page=int(page) if page is not None else None,
        snippet=str(raw.get("snippet", "")),
        score=float(score) if score is not None else None,
    )


def _event_from_payload(payload: dict[str, Any]) -> AuditEvent:
    """Reconstruct an ``AuditEvent`` from a stored JSON payload."""
    decision = Decision(str(payload["decision"]))
    citations = tuple(
        _citation_from_dict(c) for c in payload.get("citations", []) if isinstance(c, dict)
    )
    ts_raw = payload.get("timestamp")
    if not isinstance(ts_raw, str):
        raise ValueError("stored audit event has no timestamp")
    timestamp = datetime.fromisoformat(ts_raw)
    metadata_raw = payload.get("metadata", {})
    metadata = (
        {str(k): str(v) for k, v in metadata_raw.items()} if isinstance(metadata_raw, dict) else {}
    )
    return AuditEvent(
        action=str(payload.get("action", "")),
        actor=str(payload.get("actor", "")),
        decision=decision,
        redacted_prompt=str(payload.get("redacted_prompt", "")),
        redacted_response=str(payload.get("redacted_response", "")),
        citations=citations,
        resource=str(payload.get("resource", "compliance-advisory")),
        trace_id=(str(payload["trace_id"]) if payload.get("trace_id") else None),
        span_id=(str(payload["span_id"]) if payload.get("span_id") else None),
        correlation_id=(str(payload["correlation_id"]) if payload.get("correlation_id") else None),
        run_id=(str(payload["run_id"]) if payload.get("run_id") else None),
        event_id=str(payload.get("event_id", "")),
        schema_version=str(payload.get("schema_version", "audit-event/v2")),
        timestamp=timestamp,
        metadata=metadata,
    )
