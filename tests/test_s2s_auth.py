"""S2S auth tests for the WORM ingest (plan-hrz-s2s-auth).

A DELIBERATELY chosen ``local`` profile, and EXACTLY that string, is fail-open when
OBSERVABILITY_S2S_TOKEN is unset (so the offline gate runs with zero secrets) and fail-closed
when it is set or set to an empty value. Every other profile value, and the state where no
profile was chosen at all, refuses an unset token. /healthz stays open either way.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from conftest import LOOPBACK_PEER
from helpers import sample_event
from observability.api.app import create_app
from observability.api.security import _ALLOWED_CALLERS_ENV, _AUDIENCE_ENV, _TOKEN_ENV
from observability.config import LocalSettings, Settings

# The port->adapter bindings (mirrors config/settings.yaml); the local audit store is
# ephemeral in-memory so each client is deterministic.
_ADAPTER_BINDINGS = {
    "audit": {
        "gcp": "observability.adapters.gcp.cloud_logging_audit:CloudLoggingAuditAdapter",
        "local": "observability.adapters.local.audit:LocalAppendOnlyAuditAdapter",
        "onprem": "observability.adapters.onprem.audit:OnPremAuditAdapter",
    }
}


def _client(profile: str = "local") -> TestClient:
    settings = Settings(
        profile=profile,
        local=LocalSettings(audit_path=":memory:"),
        adapters=_ADAPTER_BINDINGS,
    )
    return TestClient(create_app(settings), client=LOOPBACK_PEER)


def _secure_client() -> TestClient:
    bindings = {
        "audit": {
            "gcp": "observability.adapters.local.audit:LocalAppendOnlyAuditAdapter",
        }
    }
    settings = Settings(
        profile="gcp",
        local=LocalSettings(audit_path=":memory:"),
        adapters=bindings,
    )
    return TestClient(create_app(settings), client=LOOPBACK_PEER)


@pytest.fixture()
def token_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv(_TOKEN_ENV, "s3cret-service-token")
    yield "s3cret-service-token"


def test_no_token_configured_is_open_loopback_dev():
    # OBSERVABILITY_S2S_TOKEN unset: the offline default, still writable (zero-secret CI).
    assert _client().post("/v1/audit", json=sample_event()).status_code == 202


def test_healthz_never_requires_a_token(token_env):
    assert _client().get("/healthz").status_code == 200


def test_missing_token_is_401_when_enforced(token_env):
    assert _client().post("/v1/audit", json=sample_event()).status_code == 401


def test_wrong_token_is_401_when_enforced(token_env):
    resp = _client().post(
        "/v1/audit", json=sample_event(), headers={"Authorization": "Bearer nope"}
    )
    assert resp.status_code == 401


def test_correct_token_is_accepted(token_env):
    resp = _client().post(
        "/v1/audit", json=sample_event(), headers={"Authorization": f"Bearer {token_env}"}
    )
    assert resp.status_code == 202


def test_read_is_also_guarded(token_env):
    assert _client().get("/v1/audit").status_code == 401
    ok = _client().get("/v1/audit", headers={"Authorization": f"Bearer {token_env}"})
    assert ok.status_code == 200


def test_no_token_configured_still_reads_back_for_the_offline_gate(monkeypatch) -> None:
    """The zero-secret opening the offline gate depends on, stated as its own assertion."""
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    assert _client("local").get("/v1/audit").status_code == 200


def test_only_an_exact_local_profile_may_serve_without_a_token(monkeypatch) -> None:
    """RED before the commons delegation: ``onprem`` too answered 202, unauthenticated.

    The hand-rolled check here branched on ``profile != "gcp"`` and then took the
    shared-secret path, whose unset-token opening is meant to be the loopback dev demo alone.
    So ``onprem`` inherited that opening and accepted a forged audit record with no bearer
    token: absence of a token read as consent. The commons opens on an EXACT ``local`` match
    and answers 503 otherwise.

    Capitalisation typos are no longer testable HERE, because they no longer reach a request:
    ``Settings`` refuses them at construction, which is a stronger outcome than a 503 (see
    ``tests/test_profile_single_source.py``). What remains testable at this layer is the
    profile the resolver DOES produce without consent, covered by the next test.
    """
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    response = _client("onprem").post("/v1/audit", json=sample_event())
    assert response.status_code == 503, (
        "profile 'onprem' accepted an unauthenticated write; only an exact 'local' may"
    )
    assert _TOKEN_ENV in response.json()["detail"]


def test_an_unset_profile_may_not_serve_without_a_token_either(monkeypatch) -> None:
    """The same rule, for the state that is not a profile string at all: no choice made.

    RED before the three-state fix: ``OBSERVABILITY_PROFILE`` unset produced ``profile ==
    "local"`` through the YAML's ``${OBSERVABILITY_PROFILE:-local}`` default, so this write
    was accepted with 202 and no credential.
    """
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    settings = Settings(
        profile="local",
        profile_explicit=False,
        local=LocalSettings(audit_path=":memory:"),
        adapters=_ADAPTER_BINDINGS,
    )
    client = TestClient(create_app(settings), client=LOOPBACK_PEER)
    response = client.post("/v1/audit", json=sample_event())
    assert response.status_code == 503
    assert _TOKEN_ENV in response.json()["detail"]


def test_an_empty_service_token_is_not_the_zero_secret_opening(monkeypatch) -> None:
    """A token an operator SET to empty authenticates nobody, so it refuses (commons 0.5.1).

    RED against the pinned 0.5.0: a templated ``.env`` line or a missing secret-manager
    substitution left ``OBSERVABILITY_S2S_TOKEN=""``, which inherited the unset-token opening
    and served the WORM ingest unauthenticated under the ``local`` profile.
    """
    monkeypatch.setenv(_TOKEN_ENV, "")
    response = _client("local").post("/v1/audit", json=sample_event())
    assert response.status_code == 503
    assert "empty" in response.json()["detail"]


def test_the_release_approval_route_is_verified_the_same_way(monkeypatch) -> None:
    """``require_release_approver`` carried the identical hole, on the maker-checker route."""
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    body = {
        "agent_name": "demo-agent",
        "agent_version": "1.4.2",
        "eval_run_id": "eval-run-7781",
        "approval_policy_version": "policy-v3",
    }
    assert _client("onprem").post("/v1/release-approvals", json=body).status_code == 503


def test_secure_profile_rejects_an_empty_writer_allowlist(monkeypatch) -> None:
    monkeypatch.setenv(_AUDIENCE_ENV, "https://observability.example.test")
    monkeypatch.delenv(_ALLOWED_CALLERS_ENV, raising=False)
    response = _secure_client().post(
        "/v1/audit",
        json=sample_event(),
        headers={"Authorization": "Bearer signed-token"},
    )
    assert response.status_code == 503


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
