# Adoption FAQ

## Should we consume or fork Hrz5?

Consume when the event contract and managed deployment boundary fit. Fork when naming,
release cadence, evidence custody or infrastructure ownership must differ. The comparison
and dry-run rename flow are in [`../ADOPTING.md`](../ADOPTING.md).

## Which files should a bank change?

Own configuration, adapters, Terraform inputs/state, S2S registration, notification
routing and the regulator crosswalk. Keep the event, schema and port contracts stable.

## Which sibling systems integrate with Hrz5?

Hrz1 supplies redacted content, Hrz3 identifies registered workloads, Hrz4 uses telemetry
for quality monitoring, and Hrz7 emits durable review decisions. Rsk1 is a reference
producer of audit events.
