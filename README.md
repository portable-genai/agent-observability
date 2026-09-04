# `agent-observability`: Agent Observability, Audit & FinOps (`agent-observability`)

**Industries:** All GenAI (cross-industry)

> Catalog system `agent-observability` (group `hrz`). OpenTelemetry tracing + token cost/latency FinOps
> + **compliance-grade immutable (WORM) prompt/response audit**. A mandatory platform
> dependency of the **`compliance-advisory`** (`compliance-advisory`).

`agent-observability` is the platform's *system of record* for what agents did. It provides three concerns:

| Concern | What it does | Where it lives |
|---|---|---|
| **Tracing** | OpenTelemetry / Cloud Trace ingest of agent reasoning spans | `infra/otel/` (a collector: **infra, not HTTP contract**) |
| **Audit (rule R2)** | Immutable **Write-Once-Read-Many** storage of already-redacted prompt/response events in a **locked** Cloud Logging bucket | `POST /v1/audit`, `GET /v1/audit` |
| **FinOps** | Token cost / latency dashboards over a BigQuery export of the audit + trace streams | `infra/terraform` + the [FinOps note](#finops-bigquery-export) |

The deployment region is configurable, defaults to **`asia-southeast1`**, and is validated
against an approved residency allowlist.

## Documentation

- [Adopting or forking `agent-observability`](docs/ADOPTING.md)
- [Role-specific FAQs](docs/faq/README.md)
- [Presenter and unattended demo](DEMO.md)
- [Operations runbook](docs/runbook.md)
- [On-premises migration boundary](docs/onprem-migration.md)
- [Practices audit](docs/practices-audit.md)
- [Working agreement and documentation authority order](AGENTS.md)

---

## How `compliance-advisory` depends on `agent-observability`

`compliance-advisory` emits an immutable audit record at the end of every interaction (its standard answer
pipeline ends with `audit.record(redacted)`, SPEC §5). In the full platform deployment
`compliance-advisory` does **not** write Cloud Logging directly; it routes the record through `agent-observability`:

```mermaid
flowchart LR
  `compliance-advisory`["`compliance-advisory` (compliance-advisory)"] --> adapter["RemoteAuditAdapter.record(AuditEvent)"]
  adapter -->|"POST {OBSERVABILITY_URL}/v1/audit<br/>default http://localhost:8085"| `agent-observability`["`agent-observability` service"]
  `agent-observability` -->|"202 Accepted"| worm["locked Cloud Logging WORM bucket"]
```

The body `compliance-advisory` sends is `to_jsonable(AuditEvent)`; `agent-observability`'s `AuditEventModel` accepts it
field-for-field (SPEC §6, `agent-observability` contract). Because `agent-observability` owns the *locked* bucket, `compliance-advisory` cannot
tamper with or delete its own audit trail, exactly the separation a regulator expects.

* **Rule R1** (redaction at the boundary): prompts/responses arrive **already redacted**
  by `agent-guardrail-gateway`. `agent-observability` never redacts; it serialises and stores.
* **Rule R2** (immutable audit): `agent-observability` is the WORM store. Retention is `2557d` (~7 years),
  `locked = true`.

---

## HTTP API (SPEC §6, `agent-observability`)

Release approval is a separate maker-checker surface:
`POST /v1/release-approvals` is restricted to a dedicated reviewer service-account
allowlist and stamps actor, action, and `allowed` decision server-side. Ordinary
`POST /v1/audit` callers receive `403` for a forged `release-approved` action.

| Method | Path | Body / Query | Result |
|---|---|---|---|
| `POST` | `/v1/audit` | `{AuditEvent}` + optional `Idempotency-Key` | `202 Accepted` → `{"status":"accepted","event_id":"..."}`; `409` on key/payload conflict |
| `GET` | `/v1/audit` | `?actor=&action=&limit=` | `200` → `[{AuditEvent}, ...]` (recent, redacted, newest first) |
| `GET` | `/v1/audit/{event_id}` | n/a | `200` exact accepted event; `404` if absent |
| `GET` | `/healthz` | n/a | `200` → `{"status":"ok"}` |

> OTLP trace ingest is **infra** (the OTel collector), deliberately **not** in this HTTP
> contract.

Both `/v1/audit` routes require **service-to-service auth** (`Authorization: Bearer <token>`;
`gcp` verifies a Google-signed OIDC ID token against an audience + caller allowlist, exactly
`local` uses a constant-time shared secret that is open when unset, and every other profile
value refuses). A guard on the app object confines the whole service to a loopback peer unless
the caller-identity scheme the active binding names declares that it VERIFIES its caller, which
out of the box means the `gcp` profile; setting the shared secret does not lift that bound and
is not meant to. `/healthz` stays open. See SPEC §6.1.

### `AuditEvent` JSON

```json
{
  "action": "ask",
  "actor": "analyst@bank.example",
  "decision": "allowed",
  "redacted_prompt": "What does MAS require for [REDACTED] cloud outsourcing?",
  "redacted_response": "MAS Notice 658 requires ...",
  "citations": [
    {
      "source_id": "mas-658-2024",
      "regulator": "MAS",
      "jurisdiction": "SG",
      "title": "MAS Notice 658",
      "url": "https://www.mas.gov.sg/notice-658",
      "version": "2024-06",
      "page": 12,
      "snippet": "Outsourcing arrangements must ...",
      "score": 0.91
    }
  ],
  "resource": "compliance-advisory",
  "trace_id": "0af7651916cd43dd8448eb211c80319c",
  "timestamp": "2026-06-20T03:21:00+00:00",
  "metadata": { "tokens_in": "412", "tokens_out": "188", "latency_ms": "1240" }
}
```

* `decision` ∈ `"allowed" | "blocked" | "escalated"`.
* `event_id` is caller-supplied or server-generated and is returned by ingest. Reusing an
  idempotency key with identical content returns the same id; different content is rejected.
* `metadata` is the FinOps carrier: put `tokens_in` / `tokens_out` / `latency_ms` here;
  the BigQuery export turns them into cost & latency dashboards.

### Try it

```bash
curl -s localhost:8085/healthz

curl -s -XPOST localhost:8085/v1/audit -H 'content-type: application/json' -d '{
  "action":"ask","actor":"analyst@bank.example","decision":"allowed",
  "redacted_prompt":"p","redacted_response":"r"}'

curl -s 'localhost:8085/v1/audit?actor=analyst@bank.example&limit=20'
```

---

## Architecture: ports & adapters

The persistence concern is a single port, `AuditSinkPort` (`record` + `read_recent`).
Three interchangeable adapter families implement it; the active `profile` selects one:

```mermaid
flowchart LR
  post["POST /v1/audit"] --> app
  get["GET /v1/audit"] --> app
  cli["agent-observability CLI"] --> container
  subgraph `agent-observability`["`agent-observability` service"]
    app["FastAPI app"] --> container["Container"] --> port["AuditSinkPort"]
  end
  port -->|"profile=gcp"| gcp["CloudLoggingAuditAdapter: locked Cloud Logging bucket (WORM, ~7y), lazy google-cloud-logging import"]
  port -->|"profile=local"| local["LocalAppendOnlyAuditAdapter: append-only SQLite WORM stand-in, SDK-free, seedable, optional Firestore emulator"]
  port -->|"profile=onprem"| onprem["OnPremAuditAdapter: fail-fast Google Distributed Cloud placeholder, NotImplementedError"]
```

| Profile | Backend | Google Cloud SDK | Use |
|---|---|---|---|
| `gcp` | locked Cloud Logging bucket (WORM, ~7y) + BigQuery FinOps export | required (`[gcp]` extra), imports **lazy** | production compliance store |
| `local` | append-only SQLite WORM stand-in (`~/.observability/audit.db` or `:memory:`) | none | dev / test default, runs fully offline |
| `onprem` | fail-fast placeholder (constructs + satisfies the Protocol, every method raises) | none | Google Distributed Cloud migration target |

* **`gcp`**: the compliance store. Writes to a *locked* Cloud Logging bucket; read-back
  queries the Cloud Logging API. SDK imports are **lazy** so the module imports without
  the SDK present.
* **`local`**: an append-only, bounded, thread-safe SQLite WORM stand-in. Deterministic
  and seedable, so the service runs and the tests pass **with no Google Cloud SDK, no API
  key, and no emulators**. It emulates the Write-Once-Read-Many guarantee within the store
  (no update / delete path). It is a stand-in for demos / dev, *not* the durable
  regulator-grade store (that is `gcp`).
* **`onprem`**: the Google Distributed Cloud migration target. Constructs cleanly and
  structurally satisfies the same Protocol, but every method raises `NotImplementedError`
  so a port never silently drops a compliance record. No open-source product is named.

### Optional: higher-fidelity local with the Firestore emulator

The `local` audit store defaults to SQLite (there is no Cloud Logging emulator). For a
higher-fidelity local run you can route the same append-only records to Google's official
**Firestore emulator**: install the `[gcp]` extra plus the `google-cloud-firestore`
client, start the emulator, and set `FIRESTORE_EMULATOR_HOST`. The google client is
imported **lazily inside that branch only**, so the default SDK-free path and the offline
tests never import a google-cloud package.

```bash
pip install -e '.[gcp]' google-cloud-firestore
gcloud emulators firestore start --host-port=localhost:8080   # in another shell
export FIRESTORE_EMULATOR_HOST=localhost:8080
```

The emulator branch is best-effort: records are appended without the SQLite path's
`max_events` pruning, so the emulator-backed store grows unbounded for the demo session.

---

## Run locally (local profile, no GCP)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'

# End-to-end offline: seed a tiny synthetic corpus, then read back a real cited artifact.
agent-observability seed
agent-observability read --limit 5     # newest-first, page-cited audit records
# or in one step:
make smoke

agent-observability audit verify              # re-derive the hash chain over the trail
agent-observability audit export --path trail.jsonl   # open JSON Lines, hashes included
agent-observability audit restore --path trail.jsonl  # into a fresh store, links re-verified

make run            # uvicorn on :8085  (agent-observability serve)
make test           # pytest, fully offline (local profile)
make eval           # offline audit-integrity gate (rule R2)
make lint           # ruff
make demo-selftest  # unattended assertion-backed demo
make portability-demo # bounded profile/runtime/JSON proof
make check          # complete offline gate
```

`agent-observability read` prints the immutable audit records with regulator-grade
provenance (`[source_id, REGULATOR vX p.N] url`). Under `onprem` the same command exits
`2` with the migration message (the placeholder never fabricates a record). Point `compliance-advisory` at
the service with `export OBSERVABILITY_URL=http://localhost:8085`.

---

## Configuration

All config is in `config/settings.yaml` with `${ENV:-default}` interpolation, except the two
security-relevant settings below, which are resolved in **three** states (unset,
set-and-empty, set-and-valid) because `${ENV:-default}` cannot tell a variable nobody set
from one an operator deliberately emptied.

| Env var | Default | Meaning |
|---|---|---|
| `GOOGLE_CLOUD_PROJECT` | `your-gcp-project` | GCP project id |
| `OBSERVABILITY_PROFILE` | none: unset is not a profile | `gcp` \| `local` \| `onprem`, matched exactly. Unset or empty binds the `local` adapters but consents to nothing: the WORM ingest refuses every caller and the service stays on loopback. An unknown or mis-capitalised value fails the boot. |
| `OBSERVABILITY_LOCAL_AUDIT` | `~/.observability/audit.db` | local SQLite WORM store path (`:memory:` for ephemeral) |
| `OBSERVABILITY_LOCAL_ANCHOR` | `<audit path>.anchor.json` | external chain-head anchor; put it on another volume |
| `OBSERVABILITY_ALLOWED_REGIONS` | `asia-southeast1` | residency allowlist; an unlisted `GCP_REGION` fails closed at load, and so does an allowlist set to an empty value |
| `FIRESTORE_EMULATOR_HOST` | unset | optional: route the local store to the Firestore emulator |
| `OBSERVABILITY_WORM_BUCKET` | `agent-observability-worm` | locked log bucket id (gcp) |
| `OBSERVABILITY_LOG_NAME` | `agent-observability-audit` | structured log name (gcp) |
| `OBSERVABILITY_RETENTION_DAYS` | `2557` | WORM retention (~7y, rule R2) |
| `OBSERVABILITY_READBACK_DAYS` | `30` | read-back window for `GET /v1/audit` |
| `OBSERVABILITY_BQ_DATASET` | `agent_finops` | BigQuery FinOps dataset (gcp) |
| `OBSERVABILITY_MAX_EVENTS` | `1000` | local-store read-back capacity |
| `PORT` | `8085` | bind port (Cloud Run sets this) |

To run against real GCP: `pip install -e '.[gcp]'` then `export OBSERVABILITY_PROFILE=gcp`.

---

## OpenTelemetry tracing

`agent-observability` ingests agent spans via an **OpenTelemetry collector**, not via this HTTP API. A
ready-to-run collector config is in [`infra/otel/otel-collector-config.yaml`](infra/otel/otel-collector-config.yaml):
it receives OTLP (gRPC `:4317` / HTTP `:4318`), removes GenAI prompt, response, tool,
event and log-body content, batches, and exports to **Google Cloud Trace** in the selected
region. Agents (`compliance-advisory` included) set
`OTEL_EXPORTER_OTLP_ENDPOINT` to the collector and tag spans with `trace_id`; that same
`trace_id` is stored on the `AuditEvent`, so an auditor can pivot from an audit record to
its full reasoning trace.

The collector is provisioned by [`infra/terraform/otel_collector.tf`](infra/terraform/otel_collector.tf)
as an internal-only Cloud Run service that mounts the config above from Secret Manager; its
`otlp_endpoint` terraform output is the canonical URL consumers set as
`OTEL_EXPORTER_OTLP_ENDPOINT`. Direct-to-Cloud-Trace export stays the supported default for
a vertical that has no collector deployed; the collector is the aggregation path.

To also instrument *this* service's own HTTP spans, install the `[otel]` extra.

---

## FinOps: BigQuery export

Token cost and latency are carried in `AuditEvent.metadata` (`tokens_in`, `tokens_out`,
`latency_ms`). For dashboards, the locked audit log is exported to **BigQuery** via a log
sink, then queried by Looker Studio / a BigQuery dashboard.

Terraform provisions the `agent_finops` BigQuery dataset (`infra/terraform/bigquery.tf`)
and a sink that mirrors the audit log into it. Because the **locked bucket remains the
WORM system of record**, the BigQuery copy is purely analytical: safe to query, join,
and aggregate without touching the immutable trail. Example cost rollup:

```sql
SELECT
  jsonPayload.actor                                   AS actor,
  jsonPayload.action                                  AS action,
  COUNT(*)                                             AS calls,
  SUM(CAST(jsonPayload.metadata.tokens_in  AS INT64)) AS tokens_in,
  SUM(CAST(jsonPayload.metadata.tokens_out AS INT64)) AS tokens_out,
  APPROX_QUANTILES(CAST(jsonPayload.metadata.latency_ms AS INT64), 100)[OFFSET(95)] AS p95_latency_ms
FROM `your-gcp-project.agent_finops.audit_events`
WHERE DATE(timestamp) >= CURRENT_DATE() - 30
GROUP BY actor, action
ORDER BY tokens_out DESC;
```

Multiply token sums by the model's per-token price to get cost per actor / use case.

---

## Infrastructure (Terraform)

`infra/terraform/` provisions every managed resource in `var.region` (default
`asia-southeast1`):

* **Locked WORM log bucket**: `agent-observability-worm`, retention `2557d`,
  `locked = true`. **⚠ Locking is irreversible** (see the banner in `logging_worm.tf`).
* **Log sink**: routes `agent-observability-audit` into the locked bucket.
* **BigQuery dataset**: `agent_finops` + a sink mirroring the audit log for FinOps.
* **Cloud Run**: the `agent-observability` service, ingress-internal, `gcp` profile.
* **`audit_config`**: `DATA_READ` (plus `DATA_WRITE` / `ADMIN_READ`) so every *read* of
  the audit store is itself audited.
* **Org Policy**: `gcp.resourceLocations` pinned to `var.allowed_regions` and
  `gcp.restrictNonCmekServices` over logging, BigQuery and Cloud Run, so a resource created
  outside Terraform still cannot land in the wrong region or without a bank-held key.
* **CMEK**: a KMS key in `var.region`, bound per service to the log bucket, the BigQuery
  dataset and both Cloud Run services, with `key_rotation_period` as a variable.
* **VPC Service Controls**: a perimeter that ships in **dry run** (violations logged and
  allowed) with an alert on would-be denials; `vpc_sc_enforce = true` promotes the same
  spec once that alert has been quiet. Inert until you supply `access_policy_id`.

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # set project_id
terraform init && terraform plan
```

---

## Compliance map

| Item | Where |
|---|---|
| **R1** redaction at the boundary | enforced upstream (`agent-guardrail-gateway`); `agent-observability` never sees raw PII |
| **R2** immutable WORM audit | locked Cloud Logging bucket, `retention_days=2557`, `locked=true`; hash-chained, trigger-enforced, externally anchored offline stand-in (`agent-observability audit verify`) |
| **P-04** no raw PII in logs | only `redacted_*` fields stored |
| **P-08** immutable audit + read auditing | locked bucket + `DATA_READ` audit config |
| **P-03** data residency | `allowed_regions` validated at `terraform plan`, by Org Policy, and again by the app at load |
| **P-09** encryption | bank-held CMEK bound per service (`infra/terraform/cmek.tf`), rotation as a variable |
| **P-02** no lock-in | ports & adapters; `local` runs the domain off-cloud, `onprem` stub satisfies the same Protocol |

---

## Cost and latency

Size this system's cost and latency with the shared interactive calculator: [**live**](https://portable-genai.github.io/cost-latency-calculator/calc/calculator.html?system=agent-observability) or the [in-repo page](cost-latency-calculator.html). The engine and the pricing book are maintained once in [cost-latency-calculator](https://github.com/portable-genai/cost-latency-calculator).

## License

Apache-2.0. See [LICENSE](LICENSE).
