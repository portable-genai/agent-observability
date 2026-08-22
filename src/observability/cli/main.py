"""``agent-observability`` — the Typer CLI for Hrz5 Observability, Audit & FinOps.

A thin presentation layer over the single audit concern. Every command builds the wiring
from :class:`~observability.container.Container` for the active ``OBSERVABILITY_PROFILE``,
invokes the bound :class:`~observability.ports.audit.AuditSinkPort`, and pretty-prints the
result with regulator-grade provenance.

Design constraints honoured here:

* **Import-safe.** Importing this module (the ``[project.scripts]`` entry point, or
  ``--help``) must never pull in uvicorn, the Google Cloud SDKs, or FastAPI: those are
  imported *lazily inside command bodies*, so the on-prem / local profile, which installs
  no Google Cloud SDK, can still load the CLI and run ``--help``.
* **Profile-aware.** ``OBSERVABILITY_PROFILE`` selects the adapter stack. The ``onprem``
  profile binds placeholder adapters that raise ``NotImplementedError`` from every method;
  when a command trips one, the CLI fails clearly (exit code 2) with a message that names
  the migration target rather than dumping a traceback.
* **The ``local`` profile is a WORKING offline stack:** ``seed`` then ``read`` produces a
  real, page-cited audit artifact end to end with no Google Cloud, no API key, and no
  emulators (the SDK-free SQLite WORM stand-in).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, NoReturn

import typer

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime top level
    from ..container import Container
    from ..models import AuditEvent

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "Hrz5 Agent Observability, Audit & FinOps — write and read back compliance-grade "
        "immutable (WORM) audit records on the Horizon agent platform "
        "(GCP region configurable; default us-central1)."
    ),
)

# Exit codes: 2 == the active profile cannot satisfy this command (e.g. on-prem stub);
# 1 == an unexpected adapter/runtime failure. 0 == success.
_PROFILE_EXIT = 2
_RUNTIME_EXIT = 1

_CLI_ACTOR = "cli:operator"


# --------------------------------------------------------------------------- #
# Wiring helpers (all imports lazy, so this module stays import-safe)
# --------------------------------------------------------------------------- #
def _container() -> Container:
    from ..container import Container

    return Container()


def _profile_label() -> str:
    """The active profile, or a clean exit-2 when OBSERVABILITY_PROFILE names no profile.

    ``Settings`` validates the profile, so a mis-capitalised ``Local`` cannot be loaded at
    all. That is deliberate (the same refusal makes the API a boot failure rather than a
    serving app whose exposure guard silently misses), but an operator at a terminal should
    see the sentence, not a traceback, so it lands on the profile exit code like every other
    "this profile cannot do that" outcome.
    """
    from ..config import ProfileError, Settings

    try:
        return Settings.load().profile
    except ProfileError as exc:
        _fail(str(exc), code=_PROFILE_EXIT)


def _fail(message: str, *, code: int = _RUNTIME_EXIT) -> NoReturn:
    """Print a clean error to stderr and abort with ``code`` (no traceback)."""
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _run(action: str, fn: Any) -> Any:
    """Execute ``fn`` and translate adapter failures into clean CLI exit codes.

    ``NotImplementedError`` (raised by every on-prem placeholder adapter) maps to a profile
    error (exit 2) that names the migration target; anything else surfaces as a runtime
    error (exit 1). This is the single place the CLI turns exceptions into exit codes.
    """
    profile = _profile_label()
    try:
        return fn()
    except NotImplementedError as exc:
        detail = str(exc) or "method not implemented"
        _fail(
            f"'{action}' is not available under profile '{profile}'. "
            f"This profile uses placeholder adapters (on-prem migration target): {detail}",
            code=_PROFILE_EXIT,
        )
    except KeyError as exc:
        _fail(f"'{action}' has no adapter wired for profile '{profile}': {exc}", code=_PROFILE_EXIT)
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - CLI boundary: no tracebacks to operators
        _fail(f"'{action}' failed: {type(exc).__name__}: {exc}", code=_RUNTIME_EXIT)


# --------------------------------------------------------------------------- #
# Pretty-printing (citations are the point — render them precisely)
# --------------------------------------------------------------------------- #
def _fmt_citation(c: Any) -> str:
    page = f" p.{c.page}" if c.page is not None else ""
    version = f" {c.version}" if c.version and c.version != "unknown" else ""
    return f"[{c.source_id}, {c.regulator}{version}{page}] {c.url}"


def _print_event(event: AuditEvent) -> None:
    decision = event.decision.value if hasattr(event.decision, "value") else str(event.decision)
    color = {
        "allowed": typer.colors.GREEN,
        "escalated": typer.colors.YELLOW,
        "blocked": typer.colors.RED,
    }.get(decision, typer.colors.WHITE)
    ts = (
        event.timestamp.isoformat()
        if hasattr(event.timestamp, "isoformat")
        else str(event.timestamp)
    )
    typer.secho(f"  [{decision.upper()}] {event.action}  actor={event.actor}", fg=color, bold=True)
    typer.echo(f"    at: {ts}  trace_id={event.trace_id or '-'}")
    typer.echo(f"    prompt:   {event.redacted_prompt}")
    typer.echo(f"    response: {event.redacted_response}")
    if event.citations:
        typer.secho("    Citations:", bold=True)
        for c in event.citations:
            typer.echo(f"      - {_fmt_citation(c)}")
    if event.metadata:
        rendered = ", ".join(f"{k}={v}" for k, v in sorted(event.metadata.items()))
        typer.secho(f"    finops: {rendered}", fg=typer.colors.BRIGHT_BLACK)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
@app.command()
def seed() -> None:
    """Seed the local WORM store with the built-in synthetic audit corpus (local profile)."""

    def _do() -> tuple[int, int | None]:
        audit = _container().audit
        seed_fn = getattr(audit, "seed", None)
        if seed_fn is None:
            _fail(
                f"profile '{_profile_label()}' does not support seeding "
                "(only the local SQLite WORM stand-in is seedable).",
                code=_PROFILE_EXIT,
            )
        appended = int(seed_fn())
        count_fn = getattr(audit, "count", None)
        retained = int(count_fn()) if count_fn is not None else None
        return appended, retained

    n, retained = _run("seed", _do)
    total = f", {retained} retained" if retained is not None else ""
    typer.secho(
        f"seeded {n} audit events{total} (profile={_profile_label()}).", fg=typer.colors.GREEN
    )


@app.command()
def record(
    action: Annotated[str, typer.Option(help="Interaction action, e.g. ask / checklist.")] = "ask",
    actor: Annotated[str, typer.Option(help="Actor identity.")] = _CLI_ACTOR,
    decision: Annotated[str, typer.Option(help="allowed | blocked | escalated.")] = "allowed",
    prompt: Annotated[str, typer.Option(help="Already-redacted prompt.")] = "[REDACTED]",
    response: Annotated[str, typer.Option(help="Already-redacted response.")] = "",
) -> None:
    """Append one already-redacted audit event to immutable WORM storage."""

    def _do() -> None:
        from ..models import AuditEvent, Decision

        event = AuditEvent(
            action=action,
            actor=actor,
            decision=Decision(decision),
            redacted_prompt=prompt,
            redacted_response=response,
        )
        _container().audit.record(event)

    _run("record", _do)
    typer.secho(f"recorded 1 audit event (profile={_profile_label()}).", fg=typer.colors.GREEN)


@app.command()
def read(
    actor: Annotated[str | None, typer.Option(help="Filter by actor identity.")] = None,
    action: Annotated[str | None, typer.Option(help="Filter by action.")] = None,
    limit: Annotated[int, typer.Option(min=1, max=500, help="Max events to return.")] = 50,
) -> None:
    """Read back recent immutable audit records (newest first) for demos / regulator pulls."""

    def _do() -> list[AuditEvent]:
        return _container().audit.read_recent(actor=actor, action=action, limit=limit)

    events = _run("read", _do)
    typer.secho(
        f"Audit read-back ({len(events)} events, profile={_profile_label()})",
        bold=True,
        fg=typer.colors.GREEN,
    )
    if not events:
        typer.secho("  (no events — run 'agent-observability seed' first)", fg=typer.colors.YELLOW)
        return
    for event in events:
        _print_event(event)


audit_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "Tamper evidence for the local hash-chained WORM store: "
        "verify | export | restore | reanchor."
    ),
)
app.add_typer(audit_app, name="audit")


def _chained_store(operation: str) -> Any:
    """Return the bound audit adapter, or exit 2 when its profile is not chain-capable."""
    store = _container().audit
    if not hasattr(store, "verify_chain"):
        _fail(
            f"'audit {operation}' needs the chained local WORM store; profile "
            f"'{_profile_label()}' uses the managed locked bucket, which provides "
            "non-rewritability itself (verify it with the provider's own tooling).",
            code=_PROFILE_EXIT,
        )
    return store


@audit_app.command("verify")
def audit_verify() -> None:
    """Re-derive the hash chain over the stored trail and report any tampering."""
    report = _run("audit verify", lambda: _chained_store("verify").verify_chain())
    summary = (
        f"{report.entries} records, {report.chained} chained, {report.legacy} legacy (unchained)"
    )
    if report.ok:
        typer.secho(f"audit chain: OK — {summary}", fg=typer.colors.GREEN, bold=True)
        return
    where = f" at seq {report.first_bad_seq}" if report.first_bad_seq is not None else ""
    typer.secho(f"audit chain: TAMPERED{where} — {summary}", fg=typer.colors.RED, bold=True)
    typer.secho(f"  {report.detail}", fg=typer.colors.RED)
    raise typer.Exit(_RUNTIME_EXIT)


@audit_app.command("export")
def audit_export(
    path: Annotated[str, typer.Option(help="Destination JSON Lines file.")],
) -> None:
    """Export the trail as open-format JSON Lines: anchor header, then the chained records."""
    written = _run("audit export", lambda: _chained_store("export").export_jsonl(path))
    typer.secho(f"exported {written} audit records to {path}.", fg=typer.colors.GREEN)


@audit_app.command("restore")
def audit_restore(
    path: Annotated[str, typer.Option(help="Exported JSON Lines file to restore.")],
) -> None:
    """Restore an exported trail into an empty store, re-verifying every link."""
    restored = _run("audit restore", lambda: _chained_store("restore").import_jsonl(path))
    typer.secho(
        f"restored {restored} audit records from {path} (every link re-verified).",
        fg=typer.colors.GREEN,
    )


@audit_app.command("reanchor")
def audit_reanchor(
    confirm: Annotated[
        bool,
        typer.Option(
            "--confirm",
            help="Required: you have verified this store's integrity out of band.",
        ),
    ] = False,
) -> None:
    """Re-establish the external anchor over the store AS IT NOW STANDS (operator action).

    Appends fail closed when the store no longer matches its anchor, rather than quietly
    re-anchoring a possibly tampered store, so this is the deliberate way back. It witnesses
    the present and asserts nothing about the past: only run it once you have checked the
    trail against something the store could not write (an export held elsewhere, the managed
    bucket, a backup).
    """
    if not confirm:
        _fail(
            "'audit reanchor' rewrites the external witness from the store's current "
            "contents, which cannot prove anything about what the store held before. "
            "Verify the trail out of band first, then re-run with --confirm.",
            code=_RUNTIME_EXIT,
        )
    _run("audit reanchor", lambda: _chained_store("reanchor").reanchor())
    typer.secho(
        "external anchor re-established over the store as it now stands "
        "(this witnesses the present, not the past).",
        fg=typer.colors.YELLOW,
        bold=True,
    )


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address for the API server.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="TCP port for the API server.")] = 8085,
) -> None:
    """Run the FastAPI app (POST/GET /v1/audit, /healthz) under uvicorn."""

    def _do() -> None:
        import uvicorn

        typer.secho(
            f"serving agent-observability on http://{host}:{port} (profile={_profile_label()})",
            fg=typer.colors.GREEN,
        )
        uvicorn.run("observability.api.app:app", host=host, port=port, log_level="info")

    _run("serve", _do)


@app.command()
def eval() -> None:  # noqa: A001 - "eval" is the documented gate command name
    """Run the offline audit-pipeline eval gate (WORM round-trip + citation provenance)."""

    def _do() -> int:
        import subprocess
        import sys
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[3]
        script = repo_root / "eval" / "run_eval.py"
        if not script.exists():
            _fail(f"eval gate script not found at {script}", code=_RUNTIME_EXIT)
        typer.secho(f"running eval gate: {script}", fg=typer.colors.CYAN)
        completed = subprocess.run([sys.executable, str(script)], check=False)  # noqa: S603
        return completed.returncode

    code = _run("eval", _do)
    if code == 0:
        typer.secho("eval gate: PASS", fg=typer.colors.GREEN, bold=True)
    else:
        typer.secho("eval gate: FAIL", fg=typer.colors.RED, bold=True)
    raise typer.Exit(int(code))


if __name__ == "__main__":  # pragma: no cover
    app()
