# Adoption FAQ

## Should we consume or fork `agent-observability`?

Consume when the event contract and managed deployment boundary fit. Fork when naming,
release cadence, evidence custody or infrastructure ownership must differ. The comparison
and dry-run rename flow are in [`../ADOPTING.md`](../ADOPTING.md).

## Which files should a bank change?

Own configuration, adapters, Terraform inputs/state, S2S registration, notification
routing and the regulator crosswalk. Keep the event, schema and port contracts stable.

## Which sibling systems integrate with `agent-observability`?

`agent-guardrail-gateway` supplies redacted content, `agent-registry` identifies registered workloads, `model-quality-gate` uses telemetry
for quality monitoring, and `human-review-console` emits durable review decisions. `compliance-advisory` is a reference
producer of audit events.
