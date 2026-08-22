# On-prem migration (exit / portability): General Principle P-02

The whole point of the ports-and-adapters shape is that Hrz5's exit story is **demonstrable,
not aspirational**. Switching from the managed GCP stack to a sovereign / on-premise stack
is a one-line profile change (`OBSERVABILITY_PROFILE=onprem`) plus filling in the adapter
body. The domain core, the serialization, the FastAPI app, the CLI and the auth wiring do
not change.

## What "onprem" gives you today

Setting `OBSERVABILITY_PROFILE=onprem` rebinds the one persistence port to a placeholder
adapter under `src/observability/adapters/onprem/`. That adapter:

- constructs cleanly with **no Google Cloud SDK installed** (a single `Settings` arg), and
- structurally satisfies the same `AuditSinkPort` Protocol as the managed GCP adapter, but
- raises `NotImplementedError` from **both** methods (`record` and `read_recent`) rather
  than silently no-op'ing. An unimplemented audit sink must never drop a compliance record,
  so porting on-premise *must* supply a real immutable (WORM) audit store before the profile
  ships. Under `onprem` the CLI exits `2` with the migration message instead of fabricating
  a record.

This is what makes the contract test `tests/test_adapter_parity.py` meaningful: it reads the
dotted paths from `config/settings.yaml`, constructs the `onprem` placeholder, asserts
interface parity, and proves it is fail-fast.

## The migration checklist

Hrz5 is a single-port service, so the migration is a single, bounded adapter body (the only
file that changes):

| Port | On-prem file | What to implement |
|------|--------------|-------------------|
| `AuditSinkPort` | `onprem/audit.py` | An on-prem immutable (Write-Once-Read-Many) audit store with actor/action-filtered read-back, replacing the locked Cloud Logging bucket (rule R2, P-08) |

One more binding decides whether the deployment may be reached at all, and it is what gets you
off loopback. The shipped `onprem` caller-identity scheme (`onprem/identity.py`) declares
`caller_auth = UNIMPLEMENTED`, so the loopback exposure guard treats the deployment as one that
can authenticate nobody and refuses every non-loopback peer. Point
`api.security.CALLER_IDENTITY_BINDINGS['onprem']` at your own scheme class declaring
`caller_auth = VERIFIED`, which is a claim that the caller is resolved from something checked
SERVER SIDE against an issuer rather than from a string both sides hold. That single edit does
two things, because `SECURE_PROFILES` and the guard read the same declaration: the S2S dependency
takes the verifying path for the profile, and the bound lifts. Setting `OBSERVABILITY_S2S_TOKEN`
does not and must not: a pre-shared secret authenticates a holder of a string, and it says
nothing at all about `/healthz` and `/v1/capabilities`.

Two infrastructure concerns sit outside the port boundary and are rehosted, not
re-coded, at deploy time:

- **Tracing**: agents export OTLP to the collector, so point `OTEL_EXPORTER_OTLP_ENDPOINT`
  at an on-prem OpenTelemetry collector / trace backend. No application code changes.
- **FinOps**: the BigQuery export is a log sink over the audit stream. Repoint it at an
  on-prem warehouse; `AuditEvent.metadata` (`tokens_in` / `tokens_out` / `latency_ms`) is
  the same carrier regardless of destination.

Nothing under `src/observability/models.py` or `serialization.py` changes. The
`AuditEvent` / `Citation` / `Decision` types, `to_jsonable`, the API contract and the auth
wiring are all profile-agnostic.

## Why this matters for a regulated buyer

A regulated buyer cannot accept a compliance system of record it cannot exit. Because the
domain depends only on a Protocol, the regulator-facing property that matters, an immutable
WORM trail of already-redacted prompt/response events with page-cited provenance, survives a
platform change unchanged, and the migration is a bounded, testable piece of work rather
than a rewrite. The one caveat to carry into an on-prem build (recorded in
`docs/practices-audit.md`, check C9): the managed locked bucket is where tamper-evidence is
guaranteed today, so the on-prem `AuditSinkPort` implementation must supply an equivalent
immutable store (append-only with no update/delete path, ideally hash-chained with an
external head anchor) rather than relying on the local windowed stand-in.
