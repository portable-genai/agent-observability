"""Schema round-trip + config loading. Pure, offline."""

from __future__ import annotations

from pathlib import Path

from observability.config import REGION, Settings
from observability.models import AuditEvent, Citation, Decision
from observability.schemas import AuditEventModel, CitationModel
from observability.serialization import to_jsonable


def test_audit_event_model_round_trips_through_domain() -> None:
    event = AuditEvent(
        action="checklist",
        actor="cro@bank.example",
        decision=Decision.ESCALATED,
        redacted_prompt="p",
        redacted_response="r",
        citations=(
            Citation(source_id="s", regulator="HKMA", jurisdiction="HK", title="t", url="u"),
        ),
        trace_id="abc123",
        span_id="def456",
        correlation_id="invocation-1",
        metadata={"k": "v"},
    )
    model = AuditEventModel.from_domain(event)
    back = model.to_domain()
    assert back.action == event.action
    assert back.actor == event.actor
    assert back.decision is Decision.ESCALATED
    assert back.citations[0].regulator == "HKMA"
    assert back.trace_id == "abc123"
    assert back.span_id == "def456"
    assert back.correlation_id == "invocation-1"
    assert back.metadata == {"k": "v"}


def test_model_parses_c1_to_jsonable_payload() -> None:
    # Simulate exactly what Rsk1's remote_audit adapter POSTs: to_jsonable(AuditEvent).
    event = AuditEvent(
        action="ask",
        actor="x",
        decision=Decision.BLOCKED,
        redacted_prompt="p",
        redacted_response="r",
        citations=(
            Citation(
                source_id="s", regulator="APRA", jurisdiction="AU", title="t", url="u", page=7
            ),
        ),
    )
    payload = to_jsonable(event)
    model = AuditEventModel.model_validate(payload)
    assert model.decision == "blocked"
    assert model.citations[0].page == 7


def test_citation_model_ignores_unknown_extra_keys() -> None:
    cit = CitationModel.model_validate({"source_id": "s", "future_field": "ignored"})
    assert cit.source_id == "s"


def test_settings_load_from_repo_yaml(monkeypatch) -> None:
    monkeypatch.setenv("OBSERVABILITY_PROFILE", "local")
    cfg_path = Path(__file__).resolve().parents[1] / "config" / "settings.yaml"
    settings = Settings.load(cfg_path)
    assert settings.region == REGION == "asia-southeast1"
    assert settings.profile == "local"
    assert settings.profile_explicit is True
    assert settings.logging.retention_days == 2557  # ~7y WORM (rule R2)
    assert settings.logging.bucket_id == "agent-observability-worm"
    assert settings.finops.bigquery_dataset == "agent_finops"
    # Every port has a local AND an onprem binding (and gcp where a managed service exists).
    audit = settings.adapters["audit"]
    assert "cloud_logging_audit" in audit["gcp"]
    assert "local.audit" in audit["local"]
    assert "onprem.audit" in audit["onprem"]


def test_an_unset_profile_loads_the_adapters_but_is_not_a_deliberate_choice(monkeypatch) -> None:
    """The adapters still bind (nothing else installs offline); the CONSENT does not.

    RED before the three-state fix: nothing recorded that the profile had been inherited, so
    `local` from an unset variable was indistinguishable from `local` an operator chose, and
    the zero-secret WORM ingest opened for both.
    """
    monkeypatch.delenv("OBSERVABILITY_PROFILE", raising=False)
    cfg_path = Path(__file__).resolve().parents[1] / "config" / "settings.yaml"
    settings = Settings.load(cfg_path)
    assert settings.profile == "local"
    assert settings.profile_explicit is False
    assert settings.exposure_profile == "unconfigured"
    assert settings.service_auth_configured is False


def test_gcp_region_is_configurable_from_one_selector(monkeypatch) -> None:
    # A second region is two env values (the region and the residency allowlist it must be
    # approved against), never a fork of the configuration.
    monkeypatch.setenv("GCP_REGION", "europe-west4")
    monkeypatch.setenv("OBSERVABILITY_ALLOWED_REGIONS", "us-central1,europe-west4")
    cfg_path = Path(__file__).resolve().parents[1] / "config" / "settings.yaml"
    settings = Settings.load(cfg_path)
    assert settings.region == "europe-west4"
    assert settings.allowed_regions == ("us-central1", "europe-west4")


def test_every_port_has_local_and_onprem_bindings() -> None:
    cfg_path = Path(__file__).resolve().parents[1] / "config" / "settings.yaml"
    settings = Settings.load(cfg_path)
    for port_name, binding in settings.adapters.items():
        assert "local" in binding, f"port '{port_name}' has no local adapter binding"
        assert "onprem" in binding, f"port '{port_name}' has no on-prem adapter binding"
