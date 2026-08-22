"""The `agent-observability audit verify | export | restore` surface (practice C9).

RED before the 2026-08-05 chaining change: the CLI had no `audit` command group at all, so
an operator or regulator had no way to check the trail, take it out, or bring it back.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from hex_service_kit import EXPORT_FORMAT
from typer.testing import CliRunner

from observability.cli.main import app

runner = CliRunner()


def _env(tmp_path: Path, name: str = "audit.db") -> dict[str, str]:
    return {
        "OBSERVABILITY_PROFILE": "local",
        "OBSERVABILITY_LOCAL_AUDIT": str(tmp_path / name),
        "OBSERVABILITY_LOCAL_ANCHOR": str(tmp_path / f"{name}.anchor.json"),
    }


def test_verify_reports_ok_on_a_seeded_trail(tmp_path: Path) -> None:
    env = _env(tmp_path)
    assert runner.invoke(app, ["seed"], env=env).exit_code == 0

    result = runner.invoke(app, ["audit", "verify"], env=env)

    assert result.exit_code == 0
    assert "audit chain: OK" in result.stdout


def test_verify_exits_nonzero_and_names_the_tampered_record(tmp_path: Path) -> None:
    env = _env(tmp_path)
    runner.invoke(app, ["seed"], env=env)
    with sqlite3.connect(str(tmp_path / "audit.db")) as raw:
        raw.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
        raw.execute('UPDATE audit_log SET event_json = \'{"decision": "blocked"}\' WHERE seq = 1')

    result = runner.invoke(app, ["audit", "verify"], env=env)

    assert result.exit_code == 1
    assert "TAMPERED" in result.stdout


def test_export_then_restore_into_a_fresh_store(tmp_path: Path) -> None:
    env = _env(tmp_path)
    runner.invoke(app, ["seed"], env=env)
    dump = tmp_path / "trail.jsonl"

    exported = runner.invoke(app, ["audit", "export", "--path", str(dump)], env=env)
    assert exported.exit_code == 0
    assert dump.exists()
    lines = dump.read_text(encoding="utf-8").splitlines()
    # Line 1 is the anchor header the restore checks the arriving records against; the
    # records themselves start on line 2, the first of them at genesis.
    assert json.loads(lines[0])["format"] == EXPORT_FORMAT
    assert json.loads(lines[1])["prev_hash"] == ""

    fresh = _env(tmp_path, name="restored.db")
    restored = runner.invoke(app, ["audit", "restore", "--path", str(dump)], env=fresh)
    assert restored.exit_code == 0
    assert "every link re-verified" in restored.stdout
    assert runner.invoke(app, ["audit", "verify"], env=fresh).exit_code == 0


def test_managed_profile_says_so_instead_of_pretending_to_verify(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["audit", "verify"],
        env={"OBSERVABILITY_PROFILE": "onprem", "OBSERVABILITY_LOCAL_AUDIT": str(tmp_path / "x")},
    )

    assert result.exit_code == 2  # profile cannot satisfy the command


def test_a_mis_capitalised_profile_is_a_clean_exit_two_not_a_traceback(tmp_path: Path) -> None:
    """The API refuses the typo at boot; the CLI must refuse it as an operator-readable line.

    RED before the profile validation: `OBSERVABILITY_PROFILE=Local` ran the command against
    the local store as though nothing were wrong, because nothing compared the value to the
    profiles that actually bind.
    """
    result = runner.invoke(
        app,
        ["audit", "verify"],
        env={"OBSERVABILITY_PROFILE": "Local", "OBSERVABILITY_LOCAL_AUDIT": str(tmp_path / "x")},
    )

    assert result.exit_code == 2
    assert "unknown OBSERVABILITY_PROFILE 'Local'" in result.output
    assert "case-sensitive" in result.output


def test_reanchor_refuses_without_an_explicit_confirmation(tmp_path: Path) -> None:
    """It witnesses the present, not the past, so it must never be a reflex on a red verify."""
    env = _env(tmp_path)
    runner.invoke(app, ["seed"], env=env)
    Path(env["OBSERVABILITY_LOCAL_ANCHOR"]).unlink()

    result = runner.invoke(app, ["audit", "reanchor"], env=env)

    assert result.exit_code == 1
    assert "Verify the trail out of band first" in result.output
    assert not Path(env["OBSERVABILITY_LOCAL_ANCHOR"]).exists()


def test_reanchor_with_confirmation_re_establishes_the_witness(tmp_path: Path) -> None:
    env = _env(tmp_path)
    runner.invoke(app, ["seed"], env=env)
    Path(env["OBSERVABILITY_LOCAL_ANCHOR"]).unlink()
    assert runner.invoke(app, ["audit", "verify"], env=env).exit_code == 1

    result = runner.invoke(app, ["audit", "reanchor", "--confirm"], env=env)

    assert result.exit_code == 0
    assert Path(env["OBSERVABILITY_LOCAL_ANCHOR"]).exists()
    assert runner.invoke(app, ["audit", "verify"], env=env).exit_code == 0
