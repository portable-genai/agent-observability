# Security FAQ

## Can a caller authorize itself with the event actor?

No. S2S identity is verified server-side. `actor` is historical audit content, not an
authorization input. `agent-registry` owns registry and entitlement policy.

## Where is redaction enforced?

Before `agent-observability`. `agent-guardrail-gateway` owns runtime redaction; `agent-observability` accepts and stores only `redacted_*`
fields. Producers must not send raw prompts or responses.

## Does the on-premises placeholder fail open?

No. It raises before recording or reading. An adopter must implement and prove an immutable
store before enabling that profile.
