"""The service configures the fleet's logging formatter, in the process that actually ships.

This exists because the deployed service did not. Read live against the reference deployment
on 2026-09-15: of roughly 60 `severity>=ERROR` entries on `cloud_run_revision` in thirty days,
every one came from the platform's own request log or from raw stderr. Python tracebacks
arrived as multi-line `textPayload` fragments split across several entries, with no `severity`
from the application, no logger name and no trace field. `configure_logging` was called in 75
files across the workspace and in none of the seven deployed stacks.

What that cost is specific, not aesthetic. Cloud Logging reads `severity` from the payload, so
an application error was indistinguishable from an info line and could not drive a log-based
metric. `logging.googleapis.com/trace` is what puts a log line inside the request it came from,
so without it a traceback is a separate haystack. And a traceback split across N entries has no
single entry carrying the exception, which is what Error Reporting groups on.

The assertions below are about the SHIPPED shape rather than about the kit, which has its own
tests: that the module `uvicorn` serves configures logging at import, that the installed CLI
entry point does too, and that an exception renders as ONE JSON object carrying the fields the
platform reads.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from hex_service_kit.logging import reset_logging_for_tests


@pytest.fixture(autouse=True)
def _clean_logging() -> Any:
    """Each test owns the root logger, and hands it back."""
    reset_logging_for_tests()
    root = logging.getLogger()
    handlers = root.handlers[:]
    level = root.level
    yield
    reset_logging_for_tests()
    root.handlers[:] = handlers
    root.setLevel(level)


def _reimport_app(monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """Import the API module the way a shipped process does: at module scope."""
    import importlib
    import sys

    monkeypatch.setenv("OBSERVABILITY_PROFILE", profile)
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "demo-project")
    sys.modules.pop("observability.api.app", None)
    importlib.import_module("observability.api.app")


def test_importing_the_served_module_configures_logging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`uvicorn observability.api.app:app` serves the module, so import must be enough.

    Proved red before it was trusted: with the `configure_logging` call removed from module
    scope, the root logger still carries whatever pytest left on it and this assertion fails.
    """
    _reimport_app(monkeypatch, "gcp")
    root = logging.getLogger()
    assert len(root.handlers) == 1, "the kit installs exactly one handler"
    assert type(root.handlers[0].formatter).__name__ == "CloudLoggingFormatter"


def test_a_cloud_profile_error_is_one_json_object_the_platform_can_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fields are load-bearing, so they are named rather than counted.

    `severity` is what Cloud Logging colours and what a log-based metric filters on;
    `message` is where Error Reporting looks for a traceback. A record missing either is the
    state the deployment was actually in.
    """
    _reimport_app(monkeypatch, "gcp")
    formatter = logging.getLogger().handlers[0].formatter
    assert formatter is not None

    try:
        raise ValueError("citation ledger persistence failed")
    except ValueError:
        record = logging.LogRecord(
            name="observability.adapters.gcp.cloud_logging_audit",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="audit write failed",
            args=(),
            exc_info=__import__("sys").exc_info(),
        )

    payload = json.loads(formatter.format(record))
    assert payload["severity"] == "ERROR"
    assert payload["service"] == "agent-observability"
    assert payload["logger"] == "observability.adapters.gcp.cloud_logging_audit"
    # One entry carries the whole traceback, which is what Error Reporting groups on. A
    # traceback split across entries, which is what the deployment emitted, groups as nothing.
    assert "audit write failed" in payload["message"]
    assert "Traceback (most recent call last)" in payload["message"]
    assert "ValueError: citation ledger persistence failed" in payload["message"]


def test_the_offline_profile_stays_readable_at_a_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`local` is a person at a terminal running a demo, so it is text and not JSON."""
    _reimport_app(monkeypatch, "local")
    formatter = logging.getLogger().handlers[0].formatter
    assert type(formatter).__name__ == "Formatter"


def test_the_installed_cli_entry_point_configures_logging_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`[project.scripts]` names `main:app`, so a module-guard call would run for nobody.

    The regression guard for a real mistake made while writing this change: the call was first
    placed under `if __name__ == "__main__"`, which never executes for the installed console
    script. It is a Typer callback instead, and this asserts the callback is registered rather
    than asserting the source text.
    """
    from observability.cli import main as cli_main

    assert cli_main.app.registered_callback is not None
    monkeypatch.setenv("OBSERVABILITY_PROFILE", "gcp")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "demo-project")
    cli_main.app.registered_callback.callback()
    assert type(logging.getLogger().handlers[0].formatter).__name__ == "CloudLoggingFormatter"
