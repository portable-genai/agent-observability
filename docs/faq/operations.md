# Operations and features FAQ

## Is `agent-observability` a browser dashboard?

No. It is a control-plane REST API, CLI and infrastructure service. Analytics are exported
to BigQuery for institution-owned dashboards; UI is intentionally not part of this repo.

## What is stored?

Already-redacted audit events, page-level citations, decisions, trace identifiers and
bounded FinOps metadata. OpenTelemetry spans arrive through the collector, not the audit
HTTP endpoint.

## Where do failures go?

Alert and incident routing are institution-owned. Workflows needing a manual decision
should open a case in `human-review-console`; `agent-observability` preserves the resulting evidence.
