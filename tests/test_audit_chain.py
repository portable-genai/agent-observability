"""Tamper evidence for the local WORM stand-in (practice C9).

Every test here was RED before the 2026-08-05 chaining change: the store was append-only
only by having no update method, so a direct edit, an interior deletion or a truncated tail
all went undetected, and there was no export/restore that re-verified anything.

The tamper is always applied through a SEPARATE sqlite3 connection, i.e. the way a real
attacker with file access would do it, never through the adapter's own API.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from hex_service_kit import EXPORT_FORMAT, AuditChainError

from observability.adapters.local.audit import LocalAppendOnlyAuditAdapter
from observability.config import LocalSettings, Settings
from observability.models import AuditEvent, Citation, Decision


def _event(n: int) -> AuditEvent:
    return AuditEvent(
        action="ask",
        actor="analyst@bank.example",
        decision=Decision.ALLOWED,
        redacted_prompt=f"question {n} about [REDACTED] outsourcing",
        redacted_response=f"answer {n}",
        citations=(
            Citation(
                source_id="mas-658-2024",
                regulator="MAS",
                jurisdiction="SG",
                title="MAS Notice 658",
                url="https://www.mas.gov.sg/notice-658",
                version="2024-06",
                page=12,
                snippet="Outsourcing arrangements must ...",
            ),
        ),
        event_id=f"audit-{n:04d}",
    )


def _store(
    tmp_path: Path, *, max_events: int = 100, anchor: str | None = None
) -> tuple[
    LocalAppendOnlyAuditAdapter,
    str,
]:
    db = str(tmp_path / "audit.db")
    settings = Settings(
        region="us-central1",
        profile="local",
        max_events=max_events,
        local=LocalSettings(audit_path=db, anchor_path=anchor or ""),
    )
    return LocalAppendOnlyAuditAdapter(settings), db


def _fill(store: LocalAppendOnlyAuditAdapter, count: int) -> None:
    for n in range(count):
        store.record(_event(n))


# --------------------------------------------------------------------------- #
# The store enforces append-only itself (triggers), not just by API surface
# --------------------------------------------------------------------------- #
def test_direct_update_is_refused_by_the_store(tmp_path: Path) -> None:
    store, db = _store(tmp_path)
    _fill(store, 3)

    with sqlite3.connect(db) as raw, pytest.raises(sqlite3.IntegrityError, match="append-only"):
        raw.execute("UPDATE audit_log SET actor = 'attacker' WHERE seq = 2")


def test_direct_delete_is_refused_outside_a_recorded_prune(tmp_path: Path) -> None:
    store, db = _store(tmp_path)
    _fill(store, 3)

    with sqlite3.connect(db) as raw, pytest.raises(sqlite3.IntegrityError, match="append-only"):
        raw.execute("DELETE FROM audit_log WHERE seq = 2")


# --------------------------------------------------------------------------- #
# The chain catches what the triggers cannot (an attacker drops the triggers)
# --------------------------------------------------------------------------- #
def _drop_triggers(db: str) -> None:
    """What an attacker with file access does first: remove the WORM guards."""
    with sqlite3.connect(db) as raw:
        raw.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
        raw.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")


def test_clean_trail_verifies(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    _fill(store, 5)

    report = store.verify_chain()

    assert report.ok is True
    assert report.entries == 5
    assert report.chained == 5
    assert report.legacy == 0


def test_doctored_record_is_caught(tmp_path: Path) -> None:
    store, db = _store(tmp_path)
    _fill(store, 5)
    _drop_triggers(db)
    with sqlite3.connect(db) as raw:
        row = raw.execute("SELECT seq, event_json FROM audit_log ORDER BY seq LIMIT 1 OFFSET 2")
        seq, event_json = row.fetchone()
        payload = json.loads(event_json)
        payload["decision"] = "blocked"  # rewrite history: an allowed call becomes a block
        raw.execute(
            "UPDATE audit_log SET event_json = ? WHERE seq = ?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), seq),
        )

    report = store.verify_chain()

    assert report.ok is False
    assert report.first_bad_seq == seq
    assert "altered in place" in report.detail


def test_interior_deletion_is_caught(tmp_path: Path) -> None:
    store, db = _store(tmp_path)
    _fill(store, 5)
    _drop_triggers(db)
    with sqlite3.connect(db) as raw:
        raw.execute("DELETE FROM audit_log WHERE seq = (SELECT MIN(seq) + 2 FROM audit_log)")

    report = store.verify_chain()

    assert report.ok is False
    assert "does not extend the chain" in report.detail


def test_truncated_tail_is_caught_by_the_external_anchor(tmp_path: Path) -> None:
    anchor = str(tmp_path / "elsewhere" / "audit.anchor.json")
    Path(anchor).parent.mkdir(parents=True, exist_ok=True)
    store, db = _store(tmp_path, anchor=anchor)
    _fill(store, 5)
    assert store.verify_chain().ok is True

    # Drop the two newest records: a perfectly valid, shorter chain. Only the anchor,
    # which the attacker did not hold, exposes it.
    _drop_triggers(db)
    with sqlite3.connect(db) as raw:
        raw.execute("DELETE FROM audit_log WHERE seq > (SELECT MAX(seq) - 2 FROM audit_log)")

    report = store.verify_chain()

    assert report.ok is False
    assert report.first_bad_seq is None
    assert "anchor" in report.detail
    assert "truncated" in report.detail


def test_without_an_anchor_a_truncated_tail_is_honestly_undetected(tmp_path: Path) -> None:
    """The documented limit, asserted so the docstring cannot drift into overclaiming."""
    settings = Settings(
        region="us-central1",
        profile="local",
        max_events=100,
        local=LocalSettings(audit_path=":memory:"),
    )
    store = LocalAppendOnlyAuditAdapter(settings)
    _fill(store, 5)
    store._conn.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
    store._conn.execute("DELETE FROM audit_log WHERE seq > (SELECT MAX(seq) - 2 FROM audit_log)")

    assert store.verify_chain().ok is True  # shorter, still-valid chain: not detectable


# --------------------------------------------------------------------------- #
# Retention pruning stays verifiable (this repo's windowed-buffer deviation)
# --------------------------------------------------------------------------- #
def test_capacity_pruning_keeps_the_chain_verifiable(tmp_path: Path) -> None:
    store, _ = _store(tmp_path, max_events=5)
    _fill(store, 20)

    report = store.verify_chain()

    assert report.ok is True
    assert report.entries == 5  # the window, not the whole history
    assert store.count() == 5


def _forge_prune(db: str, *, erase_through_offset: int) -> tuple[int, str]:
    """The self-consistent prune forgery: no trigger is dropped, the gate is opened.

    Move the recorded watermark onto the last record that is about to be erased, delete the
    prefix through it, then close the gate again. The surviving chain then links onto the
    forged watermark, so the chain alone cannot tell this from a legitimate retention prune.
    """
    with sqlite3.connect(db) as raw:
        seq, entry = raw.execute(
            "SELECT seq, entry_hash FROM audit_log ORDER BY seq LIMIT 1 OFFSET ?",
            (erase_through_offset,),
        ).fetchone()
        raw.execute(
            "UPDATE audit_chain_state SET prune_open = 1, pruned_seq = ?, pruned_hash = ? "
            "WHERE id = 1",
            (seq, entry),
        )
        raw.execute("DELETE FROM audit_log WHERE seq <= ?", (seq,))
        raw.execute("UPDATE audit_chain_state SET prune_open = 0 WHERE id = 1")
    return int(seq), str(entry)


def test_a_watermark_with_no_seq_is_reported_not_crashed_through(tmp_path: Path) -> None:
    """RED before the watermark fix: verify_chain() raised TypeError instead of reporting.

    The watermark row holds two independently writable columns. Erase the prefix but leave
    ``pruned_seq`` NULL and ``_watermark()`` did ``int(None)``, so the tamper answer was an
    uncaught TypeError out of verify AND out of the next record(): the operator sees a
    traceback rather than the finding, and no report is produced at all. A tamper must be
    ANSWERED, and this is not an exotic state: the restore path writes exactly it.
    """
    anchor = str(tmp_path / "elsewhere" / "audit.anchor.json")
    Path(anchor).parent.mkdir(parents=True, exist_ok=True)
    store, db = _store(tmp_path, anchor=anchor)
    _fill(store, 6)
    with sqlite3.connect(db) as raw:
        seq, entry = raw.execute(
            "SELECT seq, entry_hash FROM audit_log ORDER BY seq LIMIT 1 OFFSET 2"
        ).fetchone()
        raw.execute(
            "UPDATE audit_chain_state SET prune_open = 1, pruned_seq = NULL, pruned_hash = ? "
            "WHERE id = 1",
            (entry,),
        )
        raw.execute("DELETE FROM audit_log WHERE seq <= ?", (seq,))
        raw.execute("UPDATE audit_chain_state SET prune_open = 0 WHERE id = 1")

    report = store.verify_chain()

    assert report.ok is False
    assert "watermark does not match the external anchor" in report.detail


def test_a_restored_retention_window_verifies_and_keeps_accepting_records(
    tmp_path: Path,
) -> None:
    """RED before the watermark fix: restoring a PRUNED window raised TypeError mid-import.

    Every restore test in this file used an unpruned trail, so the one branch that exists
    purely for a windowed store -- adopt the exported window's first ``prev_hash`` as the
    retention watermark -- had never been executed. It wrote ``pruned_hash`` with a NULL
    ``pruned_seq``, which ``_watermark()`` then crashed on. The documented exit story ("a
    file copy, not a migration") was therefore false for exactly the stores that prune.
    """
    source, _ = _store(tmp_path, max_events=4)
    _fill(source, 10)  # pruned: the export is a window, not the whole history
    dump = tmp_path / "window.jsonl"
    assert source.export_jsonl(dump) == 4

    target_dir = tmp_path / "restored"
    target_dir.mkdir()
    target, _ = _store(target_dir, anchor=str(target_dir / "elsewhere.anchor.json"))

    assert target.import_jsonl(dump) == 4
    assert target.verify_chain().ok is True
    target.record(_event(99))
    assert target.verify_chain().ok is True
    assert [e.event_id for e in target.read_recent(limit=10)][1:] == [
        e.event_id for e in source.read_recent(limit=10)
    ]


def test_restore_refuses_to_overwrite_an_anchor_that_witnesses_another_store(
    tmp_path: Path,
) -> None:
    """RED before the restore-path anchor check: the second re-anchoring write path.

    ``record()`` was taught to fail closed rather than re-anchor, but ``import_jsonl()``
    still called ``_write_anchor()`` unconditionally. So the way around the fail-closed
    store was to restore a trimmed export into a FRESH store path while the anchor env var
    still pointed at the live witness: the restore verified its own (shorter) trail, wrote
    the anchor from it, and the witness of the records that were dropped was gone. Restore
    is an operator command, so this is not a bare attacker path, but it re-established the
    verifier's state with no confirmation while ``reanchor`` demands ``--confirm``: the same
    act, two different bars. Now it refuses, and ``reanchor()`` is the one way through.
    """
    anchor = str(tmp_path / "elsewhere" / "audit.anchor.json")
    Path(anchor).parent.mkdir(parents=True, exist_ok=True)
    live, _ = _store(tmp_path, anchor=anchor)
    _fill(live, 6)
    dump = tmp_path / "trail.jsonl"
    live.export_jsonl(dump)
    witness_of_the_live_store = Path(anchor).read_text(encoding="utf-8")
    trimmed = dump.read_text(encoding="utf-8").splitlines()[3:]  # drop the oldest three
    (tmp_path / "trimmed.jsonl").write_text("\n".join(trimmed) + "\n", encoding="utf-8")

    fresh_dir = tmp_path / "fresh"
    fresh_dir.mkdir()
    fresh, _ = _store(fresh_dir, anchor=anchor)  # same anchor, different store

    with pytest.raises(AuditChainError, match="already witnesses"):
        fresh.import_jsonl(tmp_path / "trimmed.jsonl")

    assert Path(anchor).read_text(encoding="utf-8") == witness_of_the_live_store
    assert live.verify_chain().ok is True  # the live store's witness still stands


def test_an_unanchored_store_never_reports_bare_chain_intact(tmp_path: Path) -> None:
    """RED before the wording fix: identical 'chain intact' with and without a witness.

    Configuration decides whether truncation and a forged prune are detectable at all, and
    ``:memory:`` (and any store with no ``anchor_path``) has no witness. Reporting the same
    sentence for both cases lets an operator read "audit chain: OK" off a store where OK
    provably cannot mean what they think. The limit is in the docstring; it has to be in
    the answer the tool actually prints.
    """
    unwitnessed = LocalAppendOnlyAuditAdapter(
        Settings(
            region="us-central1",
            profile="local",
            max_events=100,
            local=LocalSettings(audit_path=":memory:"),  # no file, so no witness
        )
    )
    _fill(unwitnessed, 3)
    anchor = str(tmp_path / "elsewhere" / "audit.anchor.json")
    Path(anchor).parent.mkdir(parents=True, exist_ok=True)
    witnessed, _ = _store(tmp_path / "witnessed", anchor=anchor)
    _fill(witnessed, 3)

    bare = unwitnessed.verify_chain()
    anchored = witnessed.verify_chain()

    assert bare.ok is True
    assert "no external anchor" in bare.detail
    assert anchored.ok is True and anchored.detail == "chain intact"


def test_prefix_deletion_disguised_as_a_prune_is_caught_by_the_anchor(tmp_path: Path) -> None:
    """RED before the anchor bound the watermark: this erased half the trail and verified."""
    anchor = str(tmp_path / "elsewhere" / "audit.anchor.json")
    Path(anchor).parent.mkdir(parents=True, exist_ok=True)
    store, db = _store(tmp_path, anchor=anchor)
    _fill(store, 6)
    assert store.verify_chain().ok is True
    anchored_before = Path(anchor).read_text(encoding="utf-8")

    _forge_prune(db, erase_through_offset=2)  # erase the oldest 3 of 6

    assert Path(anchor).read_text(encoding="utf-8") == anchored_before  # anchor never touched
    report = store.verify_chain()

    assert report.ok is False
    assert "watermark does not match the external anchor" in report.detail
    assert store.count() == 3  # the records really are gone; the trail is not trustworthy


def test_without_an_anchor_a_forged_prune_is_honestly_undetected(tmp_path: Path) -> None:
    """The second documented limit, asserted so the docstring cannot drift into overclaiming.

    With nothing outside the store witnessing the prune state, a forged watermark and the
    real one are indistinguishable. The anchor is what closes this, exactly as it is what
    closes tail truncation.
    """
    settings = Settings(
        region="us-central1",
        profile="local",
        max_events=100,
        local=LocalSettings(audit_path=":memory:"),
    )
    store = LocalAppendOnlyAuditAdapter(settings)
    _fill(store, 6)
    row = store._conn.execute(
        "SELECT seq, entry_hash FROM audit_log ORDER BY seq LIMIT 1 OFFSET 2"
    ).fetchone()
    store._conn.execute(
        "UPDATE audit_chain_state SET prune_open = 1, pruned_seq = ?, pruned_hash = ? WHERE id = 1",
        (row["seq"], row["entry_hash"]),
    )
    store._conn.execute("DELETE FROM audit_log WHERE seq <= ?", (row["seq"],))
    store._conn.execute("UPDATE audit_chain_state SET prune_open = 0 WHERE id = 1")

    assert store.verify_chain().ok is True  # not detectable without an external witness


def test_one_ordinary_append_cannot_launder_a_forged_prune(tmp_path: Path) -> None:
    """RED before the append-time anchor check: the attacker needed no anchor access at all.

    Forge the prune, then let the service take ONE more ordinary request. ``_write_anchor()``
    ran on every append and re-anchored whatever the store then claimed, so verify_chain()
    went from ok=False straight back to ok=True 'chain intact' with three records erased.
    Detection held only for a verify that happened to run inside that window, which on a live
    service is a race, not a property.
    """
    anchor = str(tmp_path / "elsewhere" / "audit.anchor.json")
    Path(anchor).parent.mkdir(parents=True, exist_ok=True)
    store, db = _store(tmp_path, anchor=anchor)
    _fill(store, 6)
    anchored_before = Path(anchor).read_text(encoding="utf-8")
    _forge_prune(db, erase_through_offset=2)
    assert store.verify_chain().ok is False

    with pytest.raises(AuditChainError, match="refusing to append"):
        store.record(_event(99))

    assert Path(anchor).read_text(encoding="utf-8") == anchored_before
    report = store.verify_chain()
    assert report.ok is False
    assert "watermark does not match the external anchor" in report.detail
    assert store.count() == 3  # the forged record was not written either


def test_a_fabricated_unchained_row_is_not_reported_as_intact(tmp_path: Path) -> None:
    """RED before the commons unchained-row fix: ok=True, entries=5, detail 'chain intact'.

    The WORM triggers block UPDATE and DELETE, not INSERT, so a direct INSERT with NULL
    hashes never trips them and never touches the anchor. The fabricated event was returned
    by read_recent(), exported by export_jsonl(), and later legitimate appends kept verifying
    clean because the head query skips NULL hashes: the forgery was permanent and silent.
    """
    anchor = str(tmp_path / "elsewhere" / "audit.anchor.json")
    Path(anchor).parent.mkdir(parents=True, exist_ok=True)
    store, db = _store(tmp_path, anchor=anchor)
    _fill(store, 4)
    forged = {
        "action": "ask",
        "actor": "ceo@bank.example",
        "decision": "blocked",
        "redacted_prompt": "fabricated evidence of a block that never happened",
        "redacted_response": "",
        "citations": [],
        "resource": "compliance-advisory",
        "event_id": "audit-forged",
        "schema_version": "audit-event/v2",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "metadata": {},
    }
    with sqlite3.connect(db) as raw:  # no trigger dropped, anchor untouched
        raw.execute(
            "INSERT INTO audit_log (action, actor, decision, timestamp, event_id, event_json, "
            "prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)",
            (
                "ask",
                "ceo@bank.example",
                "blocked",
                forged["timestamp"],
                "audit-forged",
                json.dumps(forged, sort_keys=True, separators=(",", ":")),
            ),
        )

    report = store.verify_chain()

    assert report.ok is False
    assert report.entries == 5
    assert report.chained == 4
    assert report.legacy == 1
    assert "no chain hashes" in report.detail
    # It stays caught: a later legitimate append does not restore "chain intact".
    store.record(_event(9))
    assert store.verify_chain().ok is False


def test_a_downgraded_anchor_is_caught(tmp_path: Path) -> None:
    """RED before the degraded-anchor fix: stripping two keys bought back ok=True.

    Deleting only the watermark keys from the anchor (leaving the head) made the watermark
    half of the cross-check skip itself, so a forged prune verified as 'chain intact'. A
    missing witness was loud while a half-erased one was silent; both are now the same answer.
    """
    anchor = str(tmp_path / "elsewhere" / "audit.anchor.json")
    Path(anchor).parent.mkdir(parents=True, exist_ok=True)
    store, db = _store(tmp_path, anchor=anchor)
    _fill(store, 6)
    _forge_prune(db, erase_through_offset=2)
    downgraded = json.loads(Path(anchor).read_text(encoding="utf-8"))
    downgraded.pop("pruned_hash")
    downgraded.pop("pruned_seq")
    Path(anchor).write_text(json.dumps(downgraded), encoding="utf-8")

    report = store.verify_chain()

    assert report.ok is False
    assert "no retention watermark" in report.detail
    with pytest.raises(AuditChainError, match="refusing to append"):
        store.record(_event(99))


def test_reanchor_is_the_only_way_back_and_is_an_operator_decision(tmp_path: Path) -> None:
    """Recovery is deliberate: appends never re-establish a witness, an operator does."""
    anchor = str(tmp_path / "elsewhere" / "audit.anchor.json")
    Path(anchor).parent.mkdir(parents=True, exist_ok=True)
    store, _ = _store(tmp_path, anchor=anchor)
    _fill(store, 3)
    Path(anchor).unlink()

    with pytest.raises(AuditChainError, match="refusing to append"):
        store.record(_event(9))

    store.reanchor()  # after verifying the store out of band
    anchored = json.loads(Path(anchor).read_text(encoding="utf-8"))
    assert "pruned_hash" in anchored and "entry_hash" in anchored
    assert store.verify_chain().ok is True
    store.record(_event(9))
    assert store.verify_chain().ok is True


def test_a_deleted_anchor_is_caught(tmp_path: Path) -> None:
    """Removing the witness must not silently downgrade verification to the unwitnessed case."""
    anchor = str(tmp_path / "elsewhere" / "audit.anchor.json")
    Path(anchor).parent.mkdir(parents=True, exist_ok=True)
    store, db = _store(tmp_path, anchor=anchor)
    _fill(store, 4)
    Path(anchor).unlink()
    _forge_prune(db, erase_through_offset=1)

    report = store.verify_chain()

    assert report.ok is False
    assert "anchor file is missing" in report.detail


def test_the_anchor_records_the_watermark_a_legitimate_prune_advanced(tmp_path: Path) -> None:
    anchor = str(tmp_path / "elsewhere" / "audit.anchor.json")
    Path(anchor).parent.mkdir(parents=True, exist_ok=True)
    store, _ = _store(tmp_path, max_events=5, anchor=anchor)
    _fill(store, 12)

    anchored = json.loads(Path(anchor).read_text(encoding="utf-8"))
    pruned_seq, pruned_hash = store._watermark()

    assert anchored["pruned_seq"] == pruned_seq
    assert anchored["pruned_hash"] == pruned_hash
    assert store.verify_chain().ok is True


def test_a_deletion_disguised_as_pruning_still_breaks_the_watermark(tmp_path: Path) -> None:
    store, db = _store(tmp_path, max_events=5)
    _fill(store, 20)
    _drop_triggers(db)
    # Delete the oldest retained row WITHOUT advancing the recorded watermark: exactly the
    # move a windowed buffer would otherwise hide.
    with sqlite3.connect(db) as raw:
        raw.execute("DELETE FROM audit_log WHERE seq = (SELECT MIN(seq) FROM audit_log)")

    report = store.verify_chain()

    assert report.ok is False
    assert "retained window must chain onto pruned seq" in report.detail


def test_the_unchained_emulator_branch_refuses_to_claim_verification(tmp_path: Path) -> None:
    """The docstring's last "not detected" line: the emulator branch is not chained at all,
    so verify / export / restore refuse rather than report on it."""
    store, _ = _store(tmp_path)
    _fill(store, 2)
    store._use_emulator = True

    for call in (store.verify_chain, lambda: store.export_jsonl(tmp_path / "x.jsonl")):
        with pytest.raises(AuditChainError, match="chained SQLite WORM store"):
            call()


# --------------------------------------------------------------------------- #
# Open-format export / restore, every link re-verified
# --------------------------------------------------------------------------- #
def test_export_restore_round_trip_reverifies_every_link(tmp_path: Path) -> None:
    source, _ = _store(tmp_path)
    _fill(source, 6)
    dump = tmp_path / "trail.jsonl"

    assert source.export_jsonl(dump) == 6

    target_dir = tmp_path / "restored"
    target_dir.mkdir()
    target, _ = _store(target_dir)
    assert target.import_jsonl(dump) == 6
    assert target.verify_chain().ok is True
    assert [e.event_id for e in target.read_recent(limit=10)] == [
        e.event_id for e in source.read_recent(limit=10)
    ]


def test_export_format_is_the_commons_jsonl_shape(tmp_path: Path) -> None:
    """Anchor header on line 1, then the record lines in the shape they have always had.

    The header is what lets a recipient refuse a truncated export, so it is asserted as a
    header AND as a commitment: its ``entry_hash`` must be the last record's, or the file
    would carry a witness that agrees with nothing.
    """
    store, _ = _store(tmp_path)
    _fill(store, 2)
    dump = tmp_path / "trail.jsonl"
    store.export_jsonl(dump)

    lines = [json.loads(line) for line in dump.read_text(encoding="utf-8").splitlines()]
    header, records = lines[0], lines[1:]

    assert sorted(header) == ["anchor", "format"]
    assert header["format"] == EXPORT_FORMAT
    # This profile's anchor binds the retention watermark alongside the head, and the export
    # carries both: a window states which pruned record it chains onto rather than leaving
    # the recipient to adopt whatever first prev_hash it is handed.
    assert sorted(header["anchor"]) == ["entry_hash", "pruned_hash", "pruned_seq", "seq"]

    assert [sorted(r) for r in records] == [["entry_hash", "event", "prev_hash", "seq"]] * 2
    assert records[0]["prev_hash"] == ""  # genesis
    assert records[1]["prev_hash"] == records[0]["entry_hash"]
    assert header["anchor"]["entry_hash"] == records[-1]["entry_hash"]
    assert header["anchor"]["pruned_hash"] == ""  # nothing pruned: the window is the history


def test_restore_refuses_a_trail_tampered_in_transit(tmp_path: Path) -> None:
    source, _ = _store(tmp_path)
    _fill(source, 4)
    dump = tmp_path / "trail.jsonl"
    source.export_jsonl(dump)
    lines = dump.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[2])
    entry["event"]["actor"] = "attacker@bank.example"
    lines[2] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    dump.write_text("\n".join(lines) + "\n", encoding="utf-8")

    target_dir = tmp_path / "restored"
    target_dir.mkdir()
    target, _ = _store(target_dir)
    with pytest.raises(AuditChainError, match="entry_hash mismatch"):
        target.import_jsonl(dump)


def test_restore_refuses_an_export_whose_newest_records_were_dropped(tmp_path: Path) -> None:
    """The case the chain alone cannot see, and the reason the anchor travels with the file.

    Delete the last lines of an export and what remains is a shorter chain that links
    perfectly end to end: every ``prev_hash`` still extends its predecessor, every
    ``entry_hash`` still re-derives. Nothing inside the file objects, so before the header
    existed the restored store reported ``ok=True``, ``chain intact`` over a history whose
    newest decisions had been deleted in transit. Only the head the exporter committed to
    exposes it.
    """
    source, _ = _store(tmp_path)
    _fill(source, 5)
    dump = tmp_path / "trail.jsonl"
    source.export_jsonl(dump)
    lines = dump.read_text(encoding="utf-8").splitlines()
    truncated = tmp_path / "truncated.jsonl"
    truncated.write_text("\n".join(lines[:-2]) + "\n", encoding="utf-8")  # drop the newest two

    target_dir = tmp_path / "restored"
    target_dir.mkdir()
    target, _ = _store(target_dir, anchor=str(target_dir / "restored.anchor.json"))

    with pytest.raises(AuditChainError, match="missing from the tail"):
        target.import_jsonl(truncated)
    # A refusal restores nothing: no partial trail to read back, and none to re-export.
    assert target.read_recent(limit=99) == []


def test_restore_refuses_a_window_whose_oldest_records_were_dropped(tmp_path: Path) -> None:
    """The transit twin of the forged retention prune, caught by the watermark half.

    A restore adopts the first ``prev_hash`` it is handed as the retention watermark, which
    is what lets a genuinely pruned window restore at all. Drop the OLDEST lines instead of
    the newest and that same rule re-roots the window further along: the trail chains onto
    whatever now comes first and verifies clean. The exporter's own ``pruned_hash`` is the
    only thing that says which record the window was really supposed to chain onto, which is
    why the export header carries it and this restore checks it.
    """
    source, _ = _store(tmp_path)
    _fill(source, 5)
    dump = tmp_path / "trail.jsonl"
    source.export_jsonl(dump)
    lines = dump.read_text(encoding="utf-8").splitlines()
    rerooted = tmp_path / "rerooted.jsonl"  # header kept, the two oldest records dropped
    rerooted.write_text("\n".join([lines[0]] + lines[3:]) + "\n", encoding="utf-8")

    target_dir = tmp_path / "restored"
    target_dir.mkdir()
    target, _ = _store(target_dir, anchor=str(target_dir / "restored.anchor.json"))

    with pytest.raises(AuditChainError, match="missing from the head of the window"):
        target.import_jsonl(rerooted)
    assert target.read_recent(limit=99) == []


def test_a_pre_anchor_export_restores_but_is_never_reported_intact(tmp_path: Path) -> None:
    """Backward compatible on read, and honest about what that costs.

    An export written before the header existed still restores, because refusing it would
    strand trails that are perfectly good. But nothing in such a file witnesses its own tail,
    so calling the result "chain intact" would hand an operator the exact reassurance the
    header exists to stop being free. It reports unanchored until :meth:`reanchor` records an
    operator taking responsibility for a head checked out of band.
    """
    source, _ = _store(tmp_path)
    _fill(source, 4)
    dump = tmp_path / "trail.jsonl"
    source.export_jsonl(dump)
    legacy = tmp_path / "legacy.jsonl"  # the records alone, exactly as 0.6.3 wrote them
    legacy.write_text(
        "\n".join(dump.read_text(encoding="utf-8").splitlines()[1:]) + "\n", encoding="utf-8"
    )

    target_dir = tmp_path / "restored"
    target_dir.mkdir()
    target, _ = _store(target_dir, anchor=str(target_dir / "restored.anchor.json"))

    assert target.import_jsonl(legacy) == 4
    report = target.verify_chain()
    assert report.ok is False
    assert "carried no chain anchor" in report.detail

    target.reanchor()  # the operator says they checked it out of band
    assert target.verify_chain().ok is True


def test_restore_refuses_a_non_empty_store(tmp_path: Path) -> None:
    source, _ = _store(tmp_path)
    _fill(source, 3)
    dump = tmp_path / "trail.jsonl"
    source.export_jsonl(dump)

    with pytest.raises(AuditChainError, match="non-empty"):
        source.import_jsonl(dump)
