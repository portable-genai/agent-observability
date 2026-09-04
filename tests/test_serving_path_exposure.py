"""The zero-secret opening must be bounded where agent-observability actually SERVES, not in an
entry point.

agent-observability's WORM ingest is the platform's evidence of record: `POST /v1/audit` is where
every agent's immutable audit row lands. Under the `local` profile with `OBSERVABILITY_S2S_TOKEN`
unset the ingest is deliberately open, because the offline gate runs with zero secrets, and five
documents bound that opening with the words "loopback dev only". Nothing enforced it. There was no
bind guard at all in this repo, and the shipped entry point is the Dockerfile's

    CMD exec uvicorn observability.api.app:app --host 0.0.0.0 --port ${PORT}

which imports the app object. Any guard living in a `main()` would never run in a shipped
process. The executed attack was a POST from another host on the LAN with no bearer token:
202 ACCEPTED, an attacker-chosen actor, decision and redacted prompt written into the trail
that a regulator later reads back, and idempotent so it could not be distinguished by
duplication either. Forging the audit record is worse than reading it: it is evidence.

The guard therefore rides the app object returned by `create_app()`, so it holds however the
app is served, and the assertions below are against that object rather than a helper.

A second defect lives in the guard's POSTURE, and this file asserts against it. The posture read
"... and `OBSERVABILITY_S2S_TOKEN` is unset", so SETTING a service credential switched the guard
off, and `test_setting_a_token_lifts_the_bound_because_callers_are_then_authenticated` held that
open in green ink. Executed with `OBSERVABILITY_PROFILE=local`, the token set and uvicorn bound
to `0.0.0.0`, a LAN peer with no Authorization header read `/healthz` and the whole
`/v1/capabilities` manifest; under `onprem`, which the posture excluded outright, the same two
routes answered with no secret configured anywhere. The posture is now derived from the
caller-identity BINDING and from no credential at all
(`tests/test_caller_auth_posture.py` is the standing guard for that, and
`scripts/prove-exposure-matrix.sh` drives the whole matrix over a real socket).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from helpers import sample_event
from observability.api.app import _INSECURE_DEMO_ENV, create_app
from observability.api.security import _TOKEN_ENV
from observability.config import LocalSettings, Settings

_ADAPTER_BINDINGS = {
    "audit": {
        "gcp": "observability.adapters.gcp.cloud_logging_audit:CloudLoggingAuditAdapter",
        "local": "observability.adapters.local.audit:LocalAppendOnlyAuditAdapter",
        "onprem": "observability.adapters.onprem.audit:OnPremAuditAdapter",
    }
}

_LAN_PEER = ("192.168.1.37", 51234)
_LOOPBACK_PEER = ("127.0.0.1", 51234)


def _client(peer: tuple[str, int], profile: str = "local", *, explicit: bool = True) -> TestClient:
    settings = Settings(
        profile=profile,
        profile_explicit=explicit,
        local=LocalSettings(audit_path=":memory:"),
        adapters=_ADAPTER_BINDINGS,
    )
    return TestClient(create_app(settings), client=peer)


@pytest.fixture(autouse=True)
def _zero_secret_local(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exact posture under test: `local`, no token, no opt-out."""
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    monkeypatch.delenv(_INSECURE_DEMO_ENV, raising=False)


def test_a_lan_peer_cannot_forge_an_audit_record() -> None:
    """The executed attack, against the app object uvicorn is pointed at."""
    forged = sample_event(event_id="lan-attack-1")
    forged["actor"] = "attacker@evil.example"
    forged["redacted_prompt"] = "forged row from a LAN peer, no bearer token"
    response = _client(_LAN_PEER).post("/v1/audit", json=forged)
    assert response.status_code != 202, (
        "an off-loopback caller wrote an attacker-chosen row into the WORM trail; the "
        "'loopback dev only' bound on the zero-secret opening was documented, never enforced"
    )
    assert response.status_code == 503
    assert "loopback" in response.json()["detail"]


def test_the_bound_covers_read_back_and_liveness_too() -> None:
    """The bound is about exposing the service, not about the write route alone.

    Read-back is a regulator pull over already-redacted records, and `/healthz` leaks the
    profile and region of a service that should not have been reachable at all.
    """
    client = _client(_LAN_PEER)
    assert client.get("/v1/audit").status_code == 503
    assert client.get("/healthz").status_code == 503


def test_a_forwarding_header_disqualifies_a_loopback_looking_peer() -> None:
    """A relayed request cannot be loopback, whatever the scope peer says.

    uvicorn's ProxyHeadersMiddleware WRAPS the app, so by the time this guard runs the peer
    address has already been overwritten with the proxy's. The header's presence is the only
    honest signal, and a genuinely loopback-only dev run has no proxy in front of it.
    """
    response = _client(_LOOPBACK_PEER).post(
        "/v1/audit",
        json=sample_event(),
        headers={"X-Forwarded-For": "127.0.0.1"},
    )
    assert response.status_code == 503
    assert "x-forwarded-for" in response.json()["detail"]


def test_a_loopback_peer_still_gets_the_zero_secret_offline_demo() -> None:
    """The opening the offline gate depends on is preserved exactly."""
    assert _client(_LOOPBACK_PEER).post("/v1/audit", json=sample_event()).status_code == 202


def test_the_documented_opt_out_is_the_only_way_to_expose_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_INSECURE_DEMO_ENV, "1")
    assert _client(_LAN_PEER).post("/v1/audit", json=sample_event()).status_code == 202


def test_setting_a_token_does_NOT_lift_the_bound() -> None:
    """The second defect, and the assertion that must not PIN it.

    An assertion reading "setting a token lifts the bound because callers are then
    authenticated" passes a `local` LAN peer a 202. A green test asserting a fail-open
    is worse than no test: a maintainer who closes the guard breaks the build, so the guard's
    posture keeps "... and OBSERVABILITY_S2S_TOKEN is unset" in it, which means SETTING
    a service credential switches the guard OFF. Executed against this repo with
    OBSERVABILITY_PROFILE=local, the token set and uvicorn bound to 0.0.0.0: a peer at another
    address on the LAN, holding nothing, read `/healthz` and the whole `/v1/capabilities`
    manifest.

    The credential is not the point and never was. It authenticates whoever holds a symmetric
    string, it says nothing about the routes that carry no credential at all, and it is not the
    thing that decides whether this deployment can authenticate its callers. The bound scheme
    is, and under `local` that scheme declares a pre-shared key.
    """
    os.environ[_TOKEN_ENV] = "s3cret-service-token"
    try:
        client = _client(_LAN_PEER)
    finally:
        del os.environ[_TOKEN_ENV]
    authenticated = {"Authorization": "Bearer s3cret-service-token"}
    response = client.post("/v1/audit", json=sample_event(), headers=authenticated)
    assert response.status_code != 202, (
        "setting a shared secret lifted the loopback bound on a laptop demo posture; that "
        "credential authenticates a holder of a string, not a verified caller, and it says "
        "nothing at all about the routes that carry no credential"
    )
    assert response.status_code == 503
    assert client.get("/healthz").status_code == 503
    assert client.get("/v1/capabilities").status_code == 503


def test_an_unconsented_profile_is_bounded_whatever_else_is_configured() -> None:
    """Unset is not consent, and a rebinding cannot buy consent on its behalf."""
    client = _client(_LAN_PEER, explicit=False)
    assert client.get("/healthz").status_code == 503
    assert client.get("/v1/capabilities").status_code == 503


def test_the_onprem_placeholder_is_bounded_too() -> None:
    """A scheme that verifies NOBODY cannot authenticate a caller, so it is confined.

    A guard that only ever looks at `local` answers a LAN peer 200 on `/healthz` and
    `/v1/capabilities` under `OBSERVABILITY_PROFILE=onprem`. An adopter
    who binds a verifying scheme under `CALLER_IDENTITY_BINDINGS['onprem']` lifts this bound by
    that fact alone, which is the documented on-premises path.
    """
    client = _client(_LAN_PEER, "onprem")
    assert client.get("/healthz").status_code == 503
    assert client.get("/v1/capabilities").status_code == 503


def test_a_VERIFYING_caller_identity_binding_stands_the_guard_down() -> None:
    """The control, without which "everything refuses" is satisfied by an always-on guard.

    `gcp` binds the OIDC scheme, which verifies a Google-signed assertion against its issuer,
    expiry and audience before matching the caller against an allowlist, so the guard steps
    aside and the ROUTES do the refusing: a fronted deployment stays health-checkable while the
    ingest answers 503 to a caller with no verified identity policy behind it.
    """
    client = _client(_LAN_PEER, "gcp")
    assert client.get("/healthz").status_code == 200, "a fronted deployment stays checkable"
    assert client.post("/v1/audit", json=sample_event()).status_code == 503


def test_the_shipped_entry_point_serves_the_app_object_not_a_main() -> None:
    """Why the guard cannot live in an entry point: nothing shipped calls one."""
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert "uvicorn observability.api.app:app" in dockerfile


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
