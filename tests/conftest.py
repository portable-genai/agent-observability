"""Shared test fixtures. Everything here runs offline (local profile, no GCP SDKs).

The audit fixture CONSTRUCTS the real ``local`` adapter
(``observability.adapters.local.audit.LocalAppendOnlyAuditAdapter``) against an in-memory
SQLite store, so the offline in-process implementation lives once in ``adapters/local``
and the tests exercise the shipped code rather than a bespoke fake (test dedup).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from observability.adapters.local.audit import LocalAppendOnlyAuditAdapter
from observability.api.app import create_app
from observability.config import (
    FinOpsSettings,
    LocalSettings,
    LoggingSettings,
    Settings,
)

# Build-contract bindings, mirrored from config/settings.yaml so the container and the
# contract test agree on the dotted paths for every profile.
_ADAPTER_BINDINGS = {
    "audit": {
        "gcp": "observability.adapters.gcp.cloud_logging_audit:CloudLoggingAuditAdapter",
        "local": "observability.adapters.local.audit:LocalAppendOnlyAuditAdapter",
        "onprem": "observability.adapters.onprem.audit:OnPremAuditAdapter",
    }
}


@pytest.fixture
def settings() -> Settings:
    """A self-contained local-profile Settings (no settings.yaml dependency).

    The local audit store is ``:memory:`` so every test gets an ephemeral, deterministic
    WORM stand-in with no filesystem side effects.
    """
    return Settings(
        project_id="test-project",
        region="us-central1",
        profile="local",
        max_events=100,
        logging=LoggingSettings(read_back_window_days=30),
        finops=FinOpsSettings(),
        local=LocalSettings(audit_path=":memory:"),
        adapters=_ADAPTER_BINDINGS,
    )


@pytest.fixture
def audit(settings: Settings) -> LocalAppendOnlyAuditAdapter:
    """The real seeded-capable local WORM adapter (in-memory), as the unit tests' sink."""
    return LocalAppendOnlyAuditAdapter(settings)


#: Every test client declares a loopback ASGI peer. The serving-path exposure guard refuses
#: the zero-secret ``local`` posture to a non-loopback peer, and Starlette's default test peer
#: is the literal ``"testclient"``, which is not one. Spelling it out keeps the fixtures honest
#: about the posture they exercise: the loopback dev demo, never a LAN caller.
LOOPBACK_PEER = ("127.0.0.1", 51234)


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    with TestClient(app, client=LOOPBACK_PEER) as test_client:
        yield test_client
