# SPEC: Hrz5 Agent Observability, Audit & FinOps (`agent-observability`)

Catalog system **Hrz5** (group `hrz`). The platform's system of record for what agents did:
OpenTelemetry tracing, token cost / latency FinOps, and compliance-grade immutable
(Write-Once-Read-Many) prompt/response audit. A mandatory platform dependency of the Rsk1
Compliance Assistant (`compliance-advisory`). Region pinned to `asia-southeast1`.

## 1. Scope

Hrz5 owns one persistence concern as a port, plus two infra concerns:

* **Audit (rule R2)**: immutable WORM storage of already-redacted audit events. This is the
  HTTP contract (`POST` / `GET /v1/audit`) and the single domain port (`AuditSinkPort`).
* **Tracing**: OpenTelemetry span ingest via a collector (`infra/otel/`, provisioned by
  `infra/terraform/otel_collector.tf` as an internal-only Cloud Run service that mounts the
  checked-in config from Secret Manager and exposes an `otlp_endpoint` output), exported to
  Cloud Trace. Infra, not part of the HTTP contract.
* **FinOps**: token cost / latency dashboards over a BigQuery export of the audit log.

## 2. Deployment profiles

`OBSERVABILITY_PROFILE` selects the adapter family that backs every port. The same domain
and HTTP surface run unchanged on all three; only the bound adapters differ (P-02).

| Profile | Audit backend | Google Cloud SDK | Emulator | Role |
|---|---|---|---|---|
| `gcp` | locked Cloud Logging bucket (WORM, ~7y) + BigQuery FinOps export | required (`[gcp]` extra), imports lazy | n/a | production compliance store |
| `local` | append-only SQLite WORM stand-in (`~/.observability/audit.db` or `:memory:`) | none | optional Firestore (opt-in) | dev / test default, fully offline |
| `onprem` | fail-fast placeholder (constructs, satisfies the Protocol, every method raises) | none | n/a | Google Distributed Cloud migration target |

Production default is `gcp`; the dev / test default (Makefile, CI, `.env.example`) is
`local`. Under `onprem` the CLI exits `2` with the migration message.

`OBSERVABILITY_PROFILE` resolves in **three** states, not two, and unset is not a member of
the table above:

| State | Adapters bound | Relaxations (`exposure_profile`) | WORM ingest with no service token |
|---|---|---|---|
| unset, or set to an empty value | `local` (nothing else installs offline) | `unconfigured` | refused, `503` |
| set to a value in the table | that profile | that profile | open only for exactly `local` |
| set to anything else, including `Local` | none: refused | none | never reached |

The two derived strings differ because a relaxation and a restriction fail closed in
opposite directions: an unconsented run must NOT look like `local` to the zero-secret S2S
opening, and MUST look like `local` to the loopback exposure guard. A value that is present
is validated where it is read, so an unknown or mis-capitalised profile fails the boot of
`uvicorn observability.api.app:app` and exits `2` from the CLI. Surrounding whitespace is
stripped, so the value every posture comparison judges is exactly the value resolved.
`config/settings.yaml` therefore does not declare `profile:` at all, and
`Settings.from_dict` refuses the key if it reappears: `${OBSERVABILITY_PROFILE:-local}` is a
two-state read that makes an unset variable indistinguishable from a chosen `local`.

### 2.1 Local backends

* **Audit -> append-only, hash-chained SQLite.** A `sqlite3` table with an autoincrement
  sequence, trigger-enforced WORM (no UPDATE, no DELETE outside a recorded retention
  prune), a hash chain over the canonical JSON with an external anchor over both the head
  and the prune watermark (truncation and forged-prune detection), `max_events` read-back cap, newest-first
  read-back filtered by actor / action. A row carrying no chain hashes makes verification
  fail rather than count as unverified-but-fine. The anchor is not last-write-wins: an
  append is REFUSED while the store disagrees with the anchor (missing, degraded or
  mismatched), so no tamper can be laundered by the traffic that follows it, and
  re-establishing the anchor is the explicit operator action `audit reanchor --confirm`. Serialised with the domain `to_jsonable` so a
  stored event round-trips through JSON exactly like the managed Cloud Logging sink.
  Seedable with a built-in synthetic corpus (`src/observability/adapters/local/_seed.py`) so the CLI smoke
  run and the tests share one deterministic dataset.

### 2.2 Optional emulator support (opt-in, never required)

There is no official emulator for Cloud Logging, so the local audit store is SQLite by
default. For higher fidelity, the same append-only records route to Google's **Firestore
emulator** when `FIRESTORE_EMULATOR_HOST` is set AND `google-cloud-firestore` (installed
alongside the `[gcp]` extra) imports. The google client is imported lazily inside that
branch only, so the default local path and the offline tests never import a google-cloud
package.

## 3. Eval gate (Hrz4-style promotion gate)

`eval/run_eval.py` is the offline promotion gate. Hrz5's correctness is the integrity of the
immutable trail, so it drives the local SQLite WORM adapter through a write / read-back
cycle and scores (all thresholds `1.00`):

* `write_read_parity`: every written event reads back field-for-field.
* `citation_provenance`: stored citations keep their source-id set and page-level page.
* `redaction_preserved`: only `redacted_*` fields are stored (no raw-PII column).
* `newest_first_order`: read-back is newest-first and append-only.

It needs no GCP credentials and no Google Cloud SDK; CI runs it on every change.

## 4. Domain models

`observability.models` (pure standard library, no framework imports):

* `AuditEvent`: field-for-field identical to Rsk1's `AuditEvent` so `to_jsonable(event)`
  crosses the wire without translation.
* `Citation`: regulator-grade provenance (`source_id`, `regulator`, `jurisdiction`,
  `title`, `url`, `version`, `page`, `snippet`, `score`).
* `Decision`: `allowed` | `blocked` | `escalated`.

`redacted_prompt` / `redacted_response` arrive **already de-identified** by the upstream Hrz1
guardrail / DLP (rule R1, P-04). Hrz5 never redacts; it serialises, stores immutably, reads
back.

## 5. CLI

`agent-observability` (Typer; import-safe, heavy imports lazy in command bodies):

* `seed`: seed the local WORM store with the built-in synthetic audit corpus.
* `record`: append one already-redacted audit event.
* `read`: read back recent records (newest first), filtered by actor / action / limit.
* `serve`: run the FastAPI app under uvicorn.
* `eval`: run the offline audit-integrity gate.

`NotImplementedError` from the `onprem` placeholder maps to a clean exit code `2` that
names the migration target (no traceback).

## 6. HTTP contract (consumed by Rsk1)

| Method | Path | Body / Query | Result |
|---|---|---|---|
| `POST` | `/v1/audit` | `{AuditEvent}` + optional `Idempotency-Key` | `202` → `{"status":"accepted","event_id":"..."}`; `409` on conflict; `503` when the local store refuses to append because it no longer matches its external anchor (fail closed, see §2.1) |
| `GET` | `/v1/audit` | `?actor=&action=&limit=` | `200` → `[{AuditEvent}, ...]` (newest first, redacted) |
| `GET` | `/v1/audit/{event_id}` | n/a | `200` exact event; `404` if absent |
| `GET` | `/healthz` | n/a | `200` → `{"status":"ok"}` |

Both `/v1/audit` routes require service-to-service auth (§6.1); `/healthz` stays open.

`AuditEvent` JSON is exactly Rsk1's `to_jsonable(AuditEvent)` output: `action`, `actor`,
`decision`, `redacted_prompt`, `redacted_response`, `citations[]`, `resource`, `trace_id`,
`timestamp`, `metadata{}`. `decision` ∈ `allowed | blocked | escalated`. Unknown extra
keys are ignored so the contract tolerates additive changes. OTLP trace ingest is infra
(the OTel collector), deliberately not in this HTTP contract.

Rsk1's env var to reach this service: `OBSERVABILITY_URL` (default `http://localhost:8085`).

### 6.1 Service-to-service auth

The WORM ingest authenticates the *calling service* before it may write or read the trail
(`observability.api.security.require_service_caller`, applied to both `/v1/audit` routes);
`/healthz` is intentionally open for liveness. Callers present
`Authorization: Bearer <token>`, verified per profile:

The profile this rule matches on is the `exposure_profile` of section 2, never the bound
adapter profile, because the shared-secret opening is a relaxation:

* a **deliberately chosen** `local`, and **exactly** that string: a constant-time
  shared-secret compare against `OBSERVABILITY_S2S_TOKEN`. When the secret is **unset** the
  ingest stays open (loopback dev, and the offline gate runs with zero secrets); when
  **set**, a request without the matching token is `401`; when **set to an empty value** it
  is `503`, because an empty secret authenticates nobody and a variable an operator set is
  not an unset one.
* `gcp`: a Google-signed OIDC ID token, whose signature / issuer / expiry / audience
  (`OBSERVABILITY_S2S_AUDIENCE`) are verified, then the caller service account is checked
  against the `OBSERVABILITY_S2S_ALLOWED_CALLERS` allowlist (`403` if not allowed). An unset
  audience, an empty audience, or an allowlist set to an empty value is `503`, never a
  skipped check. The google verification libs import lazily, so the `local` profile needs no
  GCP SDK.
* **anything else**, including `onprem` and the `unconfigured` posture of a run where
  `OBSERVABILITY_PROFILE` was never set: the shared-secret path with no opening, so an unset
  token is `503`. A profile nobody chose is not consent to serve the WORM ingest
  unauthenticated. (A mis-capitalised `Local` never reaches this rule: it is refused at
  configuration load.)

The verification itself is `hex_service_kit.web.make_require_service_caller`; this repo
supplies only the env-var names and the profile rule. `/v1/release-approvals` uses the same
dependency against the narrower `OBSERVABILITY_RELEASE_APPROVERS` allowlist.

**The unauthenticated posture is bounded on the serving path.** `create_app()` installs
`hex_service_kit.web.add_loopback_exposure_guard` on the app object, so a posture with
nothing authenticating the caller is refused with `503` unless the ASGI peer is loopback and
the request carries no `x-forwarded-for` / `forwarded` header. The guard rides the app rather
than an entry point because the shipped Dockerfile `CMD` is
`uvicorn observability.api.app:app --host 0.0.0.0`, which never calls one.
`OBSERVABILITY_ALLOW_INSECURE_DEMO=1` is the explicit opt-out.

**What turns that bound on is the CALLER-IDENTITY BINDING, and nothing else.** Callers here are
services, and a caller is authenticated when the scheme the active binding names resolves it
from something verified SERVER SIDE against an issuer, rather than from a string both sides
already hold. The scheme DECLARES that on itself (`src/observability/ports/identity.py`, bound
per profile in `src/observability/api/security.py`):

| Profile | Caller-identity binding | Declares | Guard |
|---|---|---|---|
| unset or set to an empty value | none chosen | (no consent) | ON |
| `local` | `SharedSecretCallerIdentity`, a pre-shared string, open when unset | preshared-key | ON |
| `onprem` | `OnPremCallerIdentity`, a placeholder verifying nobody | unimplemented | ON |
| `gcp` | `OidcCallerIdentity`, a Google-signed assertion plus a caller allowlist | verified | OFF |

`SECURE_PROFILES`, which selects the verifying path in the S2S dependency, is DERIVED from the
same declarations, so the profiles that verify and the profiles the guard stands down for are
one set rather than two lists that can drift.

`OBSERVABILITY_S2S_TOKEN` takes no part in that decision. Whether a credential happens to be SET
is not evidence that this deployment can authenticate its callers, and it is no evidence at all
about `/healthz` and `/v1/capabilities`, which carry no credential by design. While it did decide
the guard, a `local` deployment with the token set answered a LAN peer holding nothing with both
of those routes, and `onprem` did the same with no secret configured anywhere. An on-premises
deployment lifts the bound by binding its own verifying scheme under
`api.security.CALLER_IDENTITY_BINDINGS['onprem']` (see `docs/onprem-migration.md`), which the
guard reads directly, not by setting a secret.

## 7. The hard gate (how "done" is judged)

In a fresh `python3.14` venv with only `[dev]` installed (no `google-cloud-*`, no
emulators):

```bash
ruff check src tests
ruff format --check src tests
pytest -m 'not integration' -q
python eval/run_eval.py
mypy src                         # best-effort
agent-observability seed && agent-observability read   # real offline artifact (local)
OBSERVABILITY_PROFILE=onprem agent-observability read   # exits 2 (fail-fast)
```
