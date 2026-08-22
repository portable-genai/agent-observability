# Demo guide: Hrz5 Agent Observability, Audit & FinOps

Step-by-step scripts for demoing Hrz5 two ways. Hrz5 is a **platform service** (REST API +
CLI, no web UI), so the demo is **terminal / curl based** (no browser, no Playwright).

- **Demo A (LOCAL, offline)** the headline flow: a bounded, append-only-by-API audit
  buffer you can seed, read back with provenance, append to, filter, and roll up for
  FinOps. Runs **fully offline** (no Google Cloud, no API key, no emulators) on SQLite.
  It demonstrates the contract, not the managed profile's compliance-grade WORM control.
- **Demo B (GCP)** the same service against the **real managed stack** in `us-central1`:
  a locked Cloud Logging WORM bucket (~7y retention) plus a BigQuery FinOps export. Same
  REST contract, different backend.

> The synthetic audit corpus is **fictional** (invented prompts/responses, plausible but
> fictional source ids). Do not run against live customer data without your own legal,
> security and model-risk sign-off. Prompts/responses arrive **already redacted** upstream
> by Hrz1 (rule R1); Hrz5 never sees raw PII.

---

## 0. Prerequisites

| Need | Demo A (local) | Demo B (GCP) | Notes |
|------|:--:|:--:|-------|
| `git` | yes | yes | clone the repo |
| **Python 3.12+** | yes | yes | the package pins `>=3.12` |
| `curl` | for the REST variant | yes | drive the REST endpoints |
| A GCP project + `gcloud` | no | yes | billing enabled; `us-central1` available |
| Terraform | no | yes | provisions the locked WORM bucket, log sink, BigQuery dataset |
| `[gcp]` extra installed | no | yes | `google-cloud-logging`, `google-cloud-bigquery` |

Install / setup references (read these once):

- Local install and profiles, see [README "Run locally"](README.md#run-locally-local-profile-no-gcp).
- Profiles and adapters (gcp / local / onprem), see [README "Architecture: ports & adapters"](README.md#architecture-ports--adapters).
- HTTP API and the `AuditEvent` shape, see [README "HTTP API"](README.md#http-api-spec-6-a5).
- Config and env vars, see [README "Configuration"](README.md#configuration) and [`config/settings.yaml`](config/settings.yaml).
- The demo scripts, see [`scripts/README.md`](scripts/README.md).
- Infrastructure (Terraform), see [README "Infrastructure (Terraform)"](README.md#infrastructure-terraform).

---

## 1. Common setup (both demos)

```bash
git clone https://github.com/portable-genai/agent-observability.git
cd agent-observability

python3.12 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'           # core + dev tooling (NO google-cloud-* packages)

# Sanity-check the offline stack before presenting:
export OBSERVABILITY_PROFILE=local
make lint typecheck test          # ruff + mypy + pytest (all local, no cloud)
```

See [README "Run locally"](README.md#run-locally-local-profile-no-gcp) for details.

---

## 2. Demo A (LOCAL, offline): guided presenter walkthrough

The recommended way to present. A single terminal script drives the **real** `local`
profile in-process, asserts each result, writes a JSON evidence artifact, and **waits for
you to press Enter** between results, so you control the pace. No cloud, no API key, no
browser.

```bash
source .venv/bin/activate
PYTHONPATH=src:tests python scripts/observability_demo.py
# or:  make demo
```

You step through, pressing Enter each time:

1. **Seed the local audit buffer** with 3 already-redacted synthetic events.
2. **Regulator pull** read back, newest first, with provenance `[source_id, REGULATOR vX p.N] url`.
3. **Append a fresh event and read it back** the retained demo window grows by one.
4. **Scoped regulator request** filter the trail by actor.
5. **FinOps rollup** token cost / latency aggregated from `AuditEvent.metadata` (the view the gcp profile exports to BigQuery).
6. **Profile guarantee** swap to `onprem`; the placeholder adapter raises `NotImplementedError`, never fabricating a record.

**What to point at:** every cited claim carries a regulator + version + page citation;
only `redacted_*` fields are stored (P-04); FinOps rides in `metadata`; the local buffer
has no public mutation route but is not tamper-evident. The GCP profile carries the locked
WORM guarantee.

To self-run with no prompts (CI / recording), set `DEMO_AUTO=1`:

```bash
DEMO_AUTO=1 DEMO_OUT=/tmp/hrz5-demo.json \
  PYTHONPATH=src:tests python scripts/observability_demo.py
# or: make demo-selftest
```

### 2.1 Raw CLI (the same flow, by hand)

```bash
export OBSERVABILITY_PROFILE=local
export OBSERVABILITY_LOCAL_AUDIT=/tmp/observability-demo/audit.db   # a shared file store

agent-observability seed                       # seed the synthetic corpus
agent-observability read --limit 5             # regulator pull, newest first, page-cited
agent-observability record \
  --action ask --actor auditor@bank.example \
  --decision allowed --prompt '[REDACTED]' --response 'Notify MAS of material outsourcing.'
agent-observability read --actor auditor@bank.example   # scoped pull
# Or one-step end-to-end: make smoke   (seed, then read back a real cited artifact)
```

Under `OBSERVABILITY_PROFILE=onprem` the same `read` exits **2** with the migration message
(the placeholder never fabricates a record).

### 2.2 Raw REST (curl, still fully offline)

Seed a **file-backed** store, point the API at the same file, then curl the endpoints:

```bash
export OBSERVABILITY_PROFILE=local
export OBSERVABILITY_LOCAL_AUDIT=/tmp/observability-demo/audit.db
agent-observability seed                       # writes the file store

make run                                        # uvicorn on http://127.0.0.1:8085

# in another shell (same OBSERVABILITY_LOCAL_AUDIT exported):
curl -s localhost:8085/healthz                          # {"status":"ok"}

curl -s 'localhost:8085/v1/audit?limit=2' | python -m json.tool      # read-back

curl -s -XPOST localhost:8085/v1/audit -H 'content-type: application/json' -d '{
  "action":"ask","actor":"analyst@bank.example","decision":"allowed",
  "redacted_prompt":"What does MAS require for [REDACTED] cloud outsourcing?",
  "redacted_response":"MAS TRM Guidelines require provider due diligence.",
  "metadata":{"tokens_in":"412","tokens_out":"188","latency_ms":"1240"}
}' -w ' HTTP=%{http_code}\n'                            # -> {"status":"accepted"} HTTP=202

curl -s 'localhost:8085/v1/audit?actor=analyst@bank.example&limit=20' | python -m json.tool
```

> The API process reads the WORM store at `OBSERVABILITY_LOCAL_AUDIT`, so export the same
> path in both shells. With the default `:memory:` store, each process gets its own
> ephemeral table and the curl GET would come back empty.

---

## 3. Demo B (GCP): the managed WORM + FinOps stack

Same REST contract, real managed services in `us-central1`: a **locked** Cloud Logging
WORM bucket (~7y retention) and a BigQuery FinOps export. Follow [README "Infrastructure (Terraform)"](README.md#infrastructure-terraform)
for the authoritative steps; the short version:

### 3.1 GCP setup

```bash
source .venv/bin/activate
pip install -e '.[gcp,dev]'                     # adds google-cloud-logging, google-cloud-bigquery

export GOOGLE_CLOUD_PROJECT=your-sg-project
export OBSERVABILITY_PROFILE=gcp
gcloud auth application-default login
```

### 3.2 Provision infra (one-time)

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars    # set project_id
make tf-init                                     # terraform init
make tf-plan                                     # review the plan
terraform apply                                  # WARNING: locking the WORM bucket is IRREVERSIBLE
cd ../..
```

The locked bucket (`agent-observability-worm`, retention `2557d`, `locked = true`) is
the WORM system of record; the BigQuery `agent_finops` dataset receives a log-sink copy for
analytics only. See the irreversibility banner in `infra/terraform/logging_worm.tf`.

### 3.3 Run and show

```bash
make run PORT=8085                               # FastAPI on :8085, profile=gcp
```

Then drive the same REST surface (writes now hit the locked Cloud Logging bucket):

```bash
curl -s localhost:8085/healthz

curl -s -XPOST localhost:8085/v1/audit -H 'content-type: application/json' -d '{
  "action":"ask","actor":"analyst@bank.example","decision":"allowed",
  "redacted_prompt":"What does MAS require for [REDACTED] cloud outsourcing?",
  "redacted_response":"MAS TRM Guidelines require provider due diligence.",
  "citations":[{"source_id":"mas-trm-guidelines","regulator":"MAS","jurisdiction":"SG",
    "title":"MAS Technology Risk Management Guidelines","url":"https://example.test/mas/trm",
    "version":"2021","page":42}],
  "metadata":{"tokens_in":"412","tokens_out":"188","latency_ms":"1240"}
}' -w ' HTTP=%{http_code}\n'

curl -s 'localhost:8085/v1/audit?actor=analyst@bank.example&limit=20' | python -m json.tool
```

FinOps dashboards come from the BigQuery export, not this API. The cost rollup query lives
in [README "FinOps: BigQuery export"](README.md#finops-bigquery-export) (token sums x model
price = cost per actor / use case; p95 latency via `APPROX_QUANTILES`).

---

## 4. Talking points

- **It is the system of record for what agents did.** Rsk1 routes every interaction's audit
  record here via `POST /v1/audit`; Hrz5 owns the *locked* bucket, so Rsk1 cannot tamper with
  or delete its own trail (the separation a regulator expects).
- **WORM, not just "logs".** Append-only, no update/delete path; the retained count is
  monotonic. Retention is ~7 years (`2557d`, `locked = true`).
- **Redact-before-store.** Only `redacted_*` fields are persisted (rule R1 upstream, P-04
  here); Hrz5 never sees raw PII.
- **Provenance is the point.** Every claim carries `[source_id, REGULATOR vX p.N] url`, so
  an auditor can pivot from an answer to its source page, and via `trace_id` to the full
  OpenTelemetry reasoning trace.
- **FinOps for free.** Token cost / latency ride in `metadata` and aggregate into BigQuery;
  no separate metering pipeline.
- **No lock-in.** Ports & adapters: `local` runs the whole thing off-cloud, `onprem` fails
  fast (never fabricates), `gcp` is the managed compliance store. Everything is pinned to
  `us-central1` (P-03).

---

## 5. Troubleshooting & cleanup

| Symptom | Fix |
|---------|-----|
| `python3.12: command not found` | Install Python 3.12+; the package pins `>=3.12`. |
| `No module named observability` from `make run` | Activate the venv first (`source .venv/bin/activate`); the Makefile uses `python3`. |
| curl GET returns `[]` after seeding | Export the **same** `OBSERVABILITY_LOCAL_AUDIT` file path in the seed shell and the API shell; the default `:memory:` store is per-process. |
| Port 8085 already in use | `make run PORT=9000` (then curl `localhost:9000`), or `agent-observability serve --port 9000`. |
| CLI exits **2** with a migration message | You are on `OBSERVABILITY_PROFILE=onprem` (fail-fast placeholder). Use `local` (Demo A) or `gcp` (Demo B). |
| `ModuleNotFoundError: google.cloud` on gcp | `pip install -e '.[gcp,dev]'`; the SDK is only in the `[gcp]` extra. |
| GCP region / permission errors | Confirm `us-central1` and the app SA's roles; see [README "Infrastructure (Terraform)"](README.md#infrastructure-terraform). |

**Stop / clean up:** Ctrl-C `make run`. The guided script writes only an ephemeral temp-dir
SQLite file (safe to delete). For GCP, the locked bucket and its audit trail are immutable
by design; to halt ingest, scale the Cloud Run service to zero or remove the app SA's write
role (the trail remains intact). `make clean` removes local caches and build artifacts.
