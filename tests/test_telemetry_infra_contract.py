from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_collector_accepts_and_exports_all_three_otel_signals() -> None:
    config = yaml.safe_load(
        (ROOT / "infra/otel/otel-collector-config.yaml").read_text(encoding="utf-8")
    )

    pipelines = config["service"]["pipelines"]
    assert set(pipelines) == {"traces", "metrics", "logs"}
    for signal in pipelines.values():
        assert signal["receivers"] == ["otlp"]
        assert signal["exporters"] == ["googlecloud"]
        assert "attributes/redact" in signal["processors"]
        assert "transform/redact_content" in signal["processors"]

    exporter = config["exporters"]["googlecloud"]
    assert exporter["sending_queue"]["enabled"] is True
    # There must be NO retry_on_failure block. The googlecloud exporter does not accept one,
    # and it is not ignored: the collector refuses the whole configuration and the container
    # never binds its port. This assertion used to require the opposite, which kept the suite
    # green while the OTLP ingest service could not start at all — the config was asserted as
    # a FILE and never as a collector that boots. Verified 2026-08-24 by running the pinned
    # image against this exact file with and without the block.
    assert "retry_on_failure" not in exporter


def test_collector_redacts_known_sensitive_content_attributes() -> None:
    config = yaml.safe_load(
        (ROOT / "infra/otel/otel-collector-config.yaml").read_text(encoding="utf-8")
    )
    actions = config["processors"]["attributes/redact"]["actions"]
    deleted = {item["key"] for item in actions if item["action"] == "delete"}

    assert {
        "gen_ai.prompt",
        "gen_ai.completion",
        "input.value",
        "output.value",
        "user.email",
        "authorization",
    } <= deleted

    transform = config["processors"]["transform/redact_content"]
    statements = "\n".join(
        statement
        for group in (*transform["trace_statements"], *transform["log_statements"])
        for statement in group["statements"]
    )
    for sentinel_field in (
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.system_instructions",
        "gen_ai.tool.definitions",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
    ):
        assert f'delete_key(attributes, "{sentinel_field}")' in statements
    assert 'set(body, "[CONTENT REDACTED]") where body != nil' in statements


def test_terraform_provisions_slo_dashboard_and_actionable_alerts() -> None:
    monitoring = (ROOT / "infra/terraform/monitoring.tf").read_text(encoding="utf-8")
    variables = (ROOT / "infra/terraform/variables.tf").read_text(encoding="utf-8")

    assert 'resource "google_monitoring_service"' in monitoring
    assert 'resource "google_monitoring_slo"' in monitoring
    assert 'resource "google_monitoring_dashboard"' in monitoring
    assert monitoring.count('resource "google_monitoring_alert_policy"') >= 2
    assert "select_slo_burn_rate" in monitoring
    assert "default     = 0.999" in variables
    assert 'variable "alert_notification_channels"' in variables
