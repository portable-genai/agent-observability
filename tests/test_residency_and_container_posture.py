"""Deploy-time posture as code: residency, CMEK, perimeter (D5) and the image (D4).

Every assertion here was RED before the 2026-08-05 posture change: the app accepted any
``GCP_REGION`` without an allowlist, the Terraform carried no Org Policy / CMEK / VPC-SC
resources, and the Dockerfile declared no HEALTHCHECK.

What these tests do NOT claim: that the posture is live. Org Policy enforcement, real CMEK
key usage and VPC-SC dry-run telemetry can only be evidenced from a named production
project. These are configuration-and-code proofs, which is the half that can be proven
offline.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from observability.config import (
    ALLOWED_REGIONS,
    LocalSettings,
    ResidencyError,
    Settings,
    resolve_allowed_regions,
)

ROOT = Path(__file__).resolve().parents[1]
TF = ROOT / "infra" / "terraform"


def _tf(name: str) -> str:
    return (TF / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# D5 — the residency allowlist is enforced at APP LOAD, not only at plan time
# --------------------------------------------------------------------------- #
def test_region_outside_the_residency_allowlist_fails_closed_at_load() -> None:
    with pytest.raises(ResidencyError) as excinfo:
        Settings(
            region="europe-west4",
            allowed_regions=("us-central1",),
            local=LocalSettings(audit_path=":memory:"),
        )

    assert "europe-west4" in str(excinfo.value)
    assert "residency allowlist" in str(excinfo.value)


def test_empty_residency_allowlist_is_an_error_not_permission_to_use_any_region() -> None:
    with pytest.raises(ResidencyError):
        Settings(region="asia-southeast1", allowed_regions=())


@pytest.mark.parametrize("value", ("", "   ", ",", " , "))
def test_an_allowlist_set_to_an_empty_value_refuses_instead_of_inheriting_the_default(
    value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Three states, not two: a variable an operator SET is never resolved to the unset default.

    An `_as_regions` that ends in `parsed or default` lets an allowlist deliberately set to an
    empty value (a templated `.env` line, a missing secret-manager substitution) fall back
    silently to the shipped single-region list, leaving the "an empty allowlist is a
    configuration error" branch in `__post_init__` unreachable from the environment. The
    refusal reaches the operator only if it is raised.
    """
    monkeypatch.setenv("OBSERVABILITY_ALLOWED_REGIONS", value)
    with pytest.raises(ResidencyError, match="OBSERVABILITY_ALLOWED_REGIONS"):
        resolve_allowed_regions(["us-central1"])


def test_an_unset_allowlist_still_takes_the_shipped_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OBSERVABILITY_ALLOWED_REGIONS", raising=False)
    assert resolve_allowed_regions(["us-central1"]) == ("us-central1",)
    assert resolve_allowed_regions(None) == ALLOWED_REGIONS


def test_a_configured_allowlist_is_used_verbatim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OBSERVABILITY_ALLOWED_REGIONS", " us-central1 , europe-west4 ")
    assert resolve_allowed_regions(["us-central1"]) == ("us-central1", "europe-west4")


def test_approved_second_region_loads_without_a_code_change() -> None:
    settings = Settings(
        region="europe-west4",
        allowed_regions=("us-central1", "europe-west4"),
        local=LocalSettings(audit_path=":memory:"),
    )

    assert settings.region == "europe-west4"


# --------------------------------------------------------------------------- #
# D5 — posture as code in Terraform
# --------------------------------------------------------------------------- #
def test_org_policy_pins_resource_locations_to_the_allowlist_and_requires_cmek() -> None:
    policy = _tf("org_policy.tf")

    assert "projects/${var.project_id}/policies/gcp.resourceLocations" in policy
    assert 'allowed_values = [for r in var.allowed_regions : "in:${r}-locations"]' in policy
    assert "projects/${var.project_id}/policies/gcp.restrictNonCmekServices" in policy
    for service in ("logging.googleapis.com", "bigquery.googleapis.com", "run.googleapis.com"):
        assert service in policy


def test_cmek_key_is_regional_rotated_and_bound_to_every_audit_bearing_service() -> None:
    cmek = _tf("cmek.tf")

    assert 'resource "google_kms_crypto_key" "audit"' in cmek
    assert "location = var.region" in cmek  # key material shares the data's residency
    assert "rotation_period = var.key_rotation_period" in cmek
    assert "roles/cloudkms.cryptoKeyEncrypterDecrypter" in cmek
    # Every audit-bearing service must be bound. What this must NOT assert is the literal
    # "service-<number>@gcp-sa-<x>" address: that pinned the guess rather than the property,
    # and the guess is wrong twice over — the agent does not exist until the service is
    # provisioned, and BigQuery's CMEK agent does not even follow the pattern
    # (bq-<number>@bigquery-encryption). Asserting the string kept this test green while the
    # apply failed with "Service account ... does not exist" (2026-08-24).
    #
    # So the binding is checked by KEY, and the address by PROVENANCE: each one has to come
    # from the service that owns it rather than from string interpolation.
    normalised = re.sub(r"[ \t]+", " ", cmek)
    for service in ("logging", "bigquery", "run"):
        assert f"{service} =" in normalised
    assert "data.google_logging_project_cmek_settings" in cmek
    assert "data.google_bigquery_default_service_account" in cmek
    assert "google_project_service_identity" in cmek
    # Comments are allowed to QUOTE the bad pattern while explaining why it is banned, so this
    # looks only at code.
    code = "\n".join(line for line in cmek.splitlines() if not line.lstrip().startswith("#"))
    assert "gcp-sa-" not in code, "service-agent addresses must be asked for, not spelled out"

    # The per-service bindings themselves, each on the resource that holds the data.
    assert "cmek_settings {" in _tf("logging_worm.tf")
    assert "default_encryption_configuration {" in _tf("bigquery.tf")
    assert "encryption_key = google_kms_crypto_key.audit.id" in _tf("cloud_run.tf")
    assert "encryption_key = google_kms_crypto_key.audit.id" in _tf("otel_collector.tf")


def test_vpc_sc_perimeter_ships_dry_run_first_and_is_promoted_by_one_variable() -> None:
    perimeter = _tf("vpc_sc.tf")
    variables = _tf("variables.tf")

    assert 'resource "google_access_context_manager_service_perimeter" "audit"' in perimeter
    assert "use_explicit_dry_run_spec = !var.vpc_sc_enforce" in perimeter
    # The dry-run spec and the enforced status carry the SAME rules, so promotion cannot
    # quietly change what is being enforced.
    assert perimeter.count("restricted_services = var.vpc_sc_restricted_services") == 2
    assert 'variable "vpc_sc_enforce"' in variables
    assert "default     = false" in variables


def test_posture_deviations_alert_instead_of_passing_silently() -> None:
    monitoring = _tf("monitoring.tf")

    assert "hrz_agent_observability_vpc_sc_dry_run_violations" in monitoring
    assert "hrz_agent_observability_residency_policy_violations" in monitoring
    assert "constraints/gcp.resourceLocations" in monitoring
    assert "constraints/gcp.restrictNonCmekServices" in monitoring
    assert monitoring.count('resource "google_monitoring_alert_policy"') >= 4


def test_a_second_region_or_tenant_is_a_tfvars_change_never_a_fork() -> None:
    tfvars = (TF / "terraform.tfvars.example").read_text(encoding="utf-8")

    for knob in (
        "allowed_regions",
        "key_rotation_period",
        "access_policy_id",
        "vpc_sc_enforce",
    ):
        assert knob in tfvars


# --------------------------------------------------------------------------- #
# D4 — container image
# --------------------------------------------------------------------------- #
def test_container_is_non_root_minimal_and_healthchecked() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "USER appuser" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "/healthz" in dockerfile
    assert "EXPOSE 8085" in dockerfile
    assert "OBSERVABILITY_PROFILE=gcp" in dockerfile
    # The healthcheck must follow $PORT, not a second hard-coded copy of it.
    assert "os.environ.get('PORT'" in dockerfile
    # Multi-stage: the build toolchain stays in the builder stage.
    runtime_stage = dockerfile.split("AS runtime", 1)[1]
    assert "pip install --no-cache-dir build" not in runtime_stage
