# Runbook: Hrz5 Agent Observability, Audit & FinOps

Operational notes for deploying and running Hrz5 (`agent-observability`) on GCP in
`asia-southeast1`. This is a reference build; adapt it to your own change-management and
model-risk sign-off before any live use. Hrz5 is a control-plane service: it has no
end-user UI and no LLM/ADK agent, it serialises and stores already-redacted audit events
and ingests OpenTelemetry traces.

## 1. Deploy

```bash
# 1. Provision infra (review the plan first; the WORM bucket lock is IRREVERSIBLE when
#    locked = true, which is the compliant default in logging_worm.tf).
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # set project_id (no default, on purpose)
terraform init -input=false && terraform plan
terraform apply

# 2. Export the outputs consumers and the runtime need.
export HRZ_OBSERVABILITY_URL="$(terraform output -raw service_uri)"   # Rsk1 posts audit here
export OBSERVABILITY_WORM_BUCKET="$(terraform output -raw worm_bucket_id)"
export OBSERVABILITY_BQ_DATASET="$(terraform output -raw finops_dataset)"
export OTEL_EXPORTER_OTLP_ENDPOINT="$(terraform output -raw otlp_endpoint)" # agents tag spans here

# 3. Install the managed stack and run the service.
pip install -e '.[gcp]'
export GOOGLE_CLOUD_PROJECT=your-sg-project OBSERVABILITY_PROFILE=gcp
gcloud auth application-default login
python -m observability serve --port 8085      # FastAPI on :8085 (Cloud Run sets PORT)
```

The service is deployed to Cloud Run as an ingress-internal service by
`infra/terraform/cloud_run.tf`; the OTel collector is a separate internal-only Cloud Run
service (`otel_collector.tf`) that mounts its config from Secret Manager. Both are
provisioned by the same `terraform apply`. Region defaults to `asia-southeast1`; other
deployment inputs are documented in `infra/terraform/variables.tf`.

The dev/test/CI default profile is `local` (SDK-free, offline), and the Makefile, CI and
`.env.example` all set `OBSERVABILITY_PROFILE=local` explicitly rather than relying on a
fallback. Select `gcp` explicitly for a real deploy, as shown above.

**Always set the variable, and match the case exactly.** Leaving `OBSERVABILITY_PROFILE`
unset (or setting it to an empty value) is not a way of asking for `local`: the local
adapters bind, but nothing has been consented, so the WORM ingest answers `503` to every
caller and the service is confined to loopback. A value that names no profile, including the
typo `Local`, is refused where it is read: `uvicorn observability.api.app:app` fails to boot
and the CLI exits `2` with the sentence. Surrounding whitespace is stripped, so a value
arriving with a trailing newline from a config map still selects the profile you meant.

## 2. Region selection and fail-fast

The Terraform `region` variable defaults to `asia-southeast1` and is guarded by a
`validation` block: an apply against a region outside `allowed_regions` fails immediately
at `terraform plan`, before anything is created. The WORM log
bucket, the BigQuery FinOps dataset, the Cloud Run service and the OTel collector are all
created in that one region, and the CMEK key ring shares it so key material does not leave
the approved jurisdiction.

Two further gates close the paths that skip Terraform. The `gcp.resourceLocations` Org
Policy (`infra/terraform/org_policy.tf`) refuses an out-of-region create made by hand, and
the app itself re-validates `GCP_REGION` against `OBSERVABILITY_ALLOWED_REGIONS` at load and
refuses to start otherwise. Set the app's `GCP_REGION` to the same selected value, and add
the region to `allowed_regions` (Terraform) and `OBSERVABILITY_ALLOWED_REGIONS` (app) when
you approve a second one. The alert "Hrz5 residency or CMEK posture violation" pages on any
Org Policy denial, so a bypass attempt is visible rather than silent.

## 2.1 Promoting the VPC Service Controls perimeter

The perimeter in `infra/terraform/vpc_sc.tf` is inert until you set `access_policy_id`, and
then applies in **dry run**: every violation is logged and allowed, and the alert "Hrz5
VPC-SC dry-run violations" surfaces it. Work through the violations (add a legitimate caller
to an access level, fix an illegitimate one) until the alert has been quiet for a full
business cycle, then set `vpc_sc_enforce = true`. The dry-run spec and the enforced status
carry the same rules, so promotion changes the mode and nothing else.

## 3. Retention and the WORM lock

The audit bucket retention is `retention_days` (default `2557`, ~7 years) and the bucket is
`locked = true` in `logging_worm.tf`. **Locking is irreversible**: retention cannot be
reduced and the bucket cannot be deleted for the full window, not even with project-owner
rights, and `terraform destroy` will not remove it. Confirm `retention_days` before the
first apply. To trial without locking, set `locked = false` in `logging_worm.tf` (NOT
compliant for production; it breaks the rule R2 WORM guarantee Rsk1 depends on). A log sink
routes `agent-observability-audit` plus all Cloud Audit Logs into the locked bucket, and an
`audit_config` enables `DATA_READ` so every read of the store is itself audited (P-08).
Only already-redacted prompts/responses are ever written (P-04, R1); Hrz5 never redacts.

## 4. Service-to-service auth

Both `/v1/audit` routes require `Authorization: Bearer <token>`; `/healthz` stays open.

* **`gcp`**: a Google-signed OIDC ID token is verified against `OBSERVABILITY_S2S_AUDIENCE`
  and the caller service account is checked against `OBSERVABILITY_S2S_ALLOWED_CALLERS`.
  Enroll each vertical's runtime service account there (and grant it `run.invoker` on the
  collector via `otel_caller_service_accounts`).
* **`local`**, and exactly that string: a constant-time shared secret from
  `OBSERVABILITY_S2S_TOKEN`. When the env var is unset the API stays open (loopback dev
  only), which is why the offline test gate runs with zero secrets; set it to require the
  token.
* **any other value**, `onprem` and a mis-typed `Local` included: the shared-secret path with
  no opening, so an unset token answers `503`. Absence of a token is not consent to serve the
  WORM ingest unauthenticated.

The verifier is the shared `hex-service-kit` commons, which was extracted from this repo's
implementation, so the env-var names and semantics are the platform reference.

### The unverified posture is confined to loopback, on the serving path

`create_app()` installs the commons exposure guard on the app object, so a posture with no
verified caller authentication answers `503` unless the peer is loopback and the request
carries no `x-forwarded-for` / `forwarded` header (a relayed request cannot be shown to be
loopback, because the proxy has already overwritten the peer address before the guard runs).
The guard is on the app rather than in an entry point because the shipped Dockerfile `CMD` is
`uvicorn observability.api.app:app --host 0.0.0.0`, so an entry-point check would never run
in a shipped process. Forging an audit record is worse than reading one: it is evidence.

**One thing switches it off: the caller-identity scheme the active binding names declaring that
it VERIFIES its caller** (`src/observability/ports/identity.py`, bound per profile in
`api/security.py`). Three situations therefore keep it on, and all three are bounded:

1. no profile was chosen, so nobody selected an authentication scheme at all;
2. `OBSERVABILITY_PROFILE=local`, where the scheme is a pre-shared string: symmetric, anonymous,
   and simply absent when nobody configured one;
3. `OBSERVABILITY_PROFILE=onprem`, where the placeholder scheme verifies nobody until an adopter
   binds a verifier.

`OBSERVABILITY_PROFILE=gcp` binds the OIDC scheme, which verifies a Google-signed assertion
against its issuer, expiry and audience and then matches the caller against an allowlist, so the
guard stands down and the routes do the refusing: `/healthz` keeps answering the platform's
health checks while both `/v1/audit` routes refuse a caller with no verified identity.

**Setting `OBSERVABILITY_S2S_TOKEN` does NOT switch the guard off.** It closes the ingest, one
route at a time, and changes nothing about `/healthz` and `/v1/capabilities`, which carry no
credential by design. While it did decide the guard, a `local` deployment with the token set
answered a LAN peer holding nothing with both of those routes, and `onprem` did the same with no
secret configured anywhere.

To serve an on-premises deployment off loopback, point
`api.security.CALLER_IDENTITY_BINDINGS['onprem']` at your own scheme class declaring
`caller_auth = VERIFIED` (see `docs/onprem-migration.md`). That one edit both selects the
verifying S2S path for the profile and lifts the bound, because `SECURE_PROFILES` and the guard
read the same declarations. `OBSERVABILITY_ALLOW_INSECURE_DEMO=1` is the only other way out, and
it accepts the exposure rather than removing it: never use it anywhere the trail is treated as
evidence.

`scripts/prove-exposure-matrix.sh` drives the whole matrix (profile x token x bearer) against
uvicorn over a real socket from this machine's LAN address, and asserts every cell.

## 5. Tracing and FinOps after deploy

Point agents (Rsk1 included) at the collector with `OTEL_EXPORTER_OTLP_ENDPOINT` (the
`otlp_endpoint` output); the same `trace_id` they tag is stored on the `AuditEvent`, so an
auditor can pivot from an audit record to its full reasoning trace. Token cost and latency
ride in `AuditEvent.metadata` (`tokens_in` / `tokens_out` / `latency_ms`); a log sink
mirrors the audit log into the `agent_finops` BigQuery dataset for cost/latency dashboards.
The locked bucket stays the WORM system of record, so the BigQuery copy is purely
analytical: safe to query and aggregate without touching the immutable trail.

## 6. Local audit store: a windowed but tamper-evident buffer

Under `local`, the SQLite stand-in (`OBSERVABILITY_LOCAL_AUDIT`, or `~/.observability/audit.db`)
is an append-only, oldest-pruned read-back **buffer** bounded by `OBSERVABILITY_MAX_EVENTS`
(default `1000`). Within that window it is tamper-evident: SQLite triggers refuse UPDATE and
refuse DELETE outside a recorded retention prune, each record is hash-chained to its
predecessor, the prune records a watermark the retained window must chain onto, and the
chain head is mirrored to `OBSERVABILITY_LOCAL_ANCHOR`.

Operator commands:

```bash
agent-observability audit verify                      # exit 0 clean, exit 1 tampered
agent-observability audit export --path trail.jsonl   # anchor header, then the chained records
agent-observability audit restore --path trail.jsonl  # into a FRESH store, links re-verified
agent-observability audit reanchor --confirm          # operator-only, see "recovery" below
```

Put the anchor on a different volume or under different credentials than the store. It holds
the chain head AND the retention-prune watermark. Without that separation an actor who can
rewrite the store can rewrite the anchor with it, and both a truncated tail and a prefix
deletion recorded as a retention prune become undetectable. `src/observability/adapters/local/audit.py` states the
detected and undetected tamper classes exactly.

### The store fails closed once it disagrees with its anchor

Appends are refused (`AuditChainError`, HTTP `503` on `POST /v1/audit`, see SPEC §6) as soon
as the store no longer matches the anchor: a divergence, a missing anchor file, or one whose
watermark keys have been removed. This is deliberate: rewriting the anchor on every append would
let a single ordinary request after a tamper re-anchor the tampered state so verification reads
green again. Refusing to append is what makes detection permanent rather than a race against the
next request. Expect an audit outage, not silent laundering.

Recovery, in order:

1. `agent-observability audit verify` and read the detail line: it names which half
   disagrees (head, watermark, missing file, degraded file).
2. Establish the truth **out of band**, against something this store could not have written:
   a previously exported `trail.jsonl` held elsewhere, a backup, or the managed bucket.
3. If the store is sound and only the witness was lost, `agent-observability audit reanchor
   --confirm` re-establishes it. It witnesses the store as it now stands and proves nothing
   about the past, which is why it is never automatic and never a side effect of an append.
4. If the store is not sound, do not re-anchor it. Restore a verified export into a fresh
   path (`audit restore`) and keep the tampered file as evidence.

Give the restored store its own `OBSERVABILITY_LOCAL_ANCHOR` as well as its own
`OBSERVABILITY_LOCAL_AUDIT`. `audit restore` refuses outright while the configured anchor
file already exists, because finishing the restore would rewrite that anchor from the trail
being imported: restoring a deliberately shortened export with the anchor still pointed at
the live witness is the same laundering move as an append, taken through the operator
surface. Once the restored store verifies, `audit reanchor --confirm` gives it a witness.

The window is still a window: it holds the most recent `OBSERVABILITY_MAX_EVENTS` records,
not seven years of them. The retention control remains the managed locked Cloud Logging
bucket, which is the deploy posture. Use `local` for demos, dev and the offline gate.

## 7. Kill switch

To stop serving without tearing down state: scale the Cloud Run deployment to zero, or
remove the caller service accounts from `OBSERVABILITY_S2S_ALLOWED_CALLERS` (and their
`run.invoker` binding) so no vertical can write or read. The locked WORM bucket and every
record already written remain intact.

## 8. Common failures

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `NotImplementedError` from a CLI command or a `record` call | `OBSERVABILITY_PROFILE=onprem` (fail-fast placeholder) | Set `OBSERVABILITY_PROFILE=gcp` or `local`, or implement the on-prem adapter |
| CLI `read`/`seed` exits `2` | `onprem` profile has no working store (never fabricates a record) | Use `local` for offline demos, `gcp` for the real store |
| `401`/`403` on `/v1/audit` | missing or wrong `Authorization` bearer, or caller not in the allowlist | Set `OBSERVABILITY_S2S_TOKEN` (local) or enroll the SA in `OBSERVABILITY_S2S_ALLOWED_CALLERS` (gcp) |
| `503` naming `OBSERVABILITY_S2S_TOKEN` | the exposure profile is not exactly `local` and no token is configured, so the caller cannot be authenticated at all. `OBSERVABILITY_PROFILE` unset or empty lands here by design: nobody chose the profile whose ingest may open | Set the token, or set `OBSERVABILITY_PROFILE` deliberately |
| `503` saying the service token is set to an empty value | `OBSERVABILITY_S2S_TOKEN` is present but blank (a templated `.env` line, a missing secret-manager substitution). An empty secret authenticates nobody | Unset the variable for the loopback dev opening, or set it to the real shared secret |
| Boot fails with `unknown OBSERVABILITY_PROFILE`, or the CLI exits `2` with it | the profile names none of `gcp` / `local` / `onprem`; the match is case-sensitive | Correct the value. It is refused rather than normalised, because a typo selects none of the profile's relaxations AND none of its restrictions |
| `503` naming loopback or a forwarding header | a posture with no VERIFIED caller authentication was reached from a non-loopback peer or through a proxy: no profile chosen, `local`, or `onprem`. Setting the S2S token does not change this and is not meant to | Serve on loopback, choose a profile whose caller-identity binding verifies (`gcp`) or bind your own verifier, or accept the exposure with `OBSERVABILITY_ALLOW_INSECURE_DEMO=1` |
| `ResidencyError` naming `OBSERVABILITY_ALLOWED_REGIONS` at load | the allowlist is present but blank or names no region; an allowlist admitting nothing is a configuration error, never "any region" | Remove the line to take the shipped allowlist, or list the approved regions |
| `terraform plan` rejects the apply | `region` is absent from `allowed_regions` | Add only a residency-approved region to the allowlist (P-03) |
| `google-cloud-*` ImportError under `gcp` | `[gcp]` extra not installed | `pip install -e '.[gcp]'` |
| Local store not growing past ~1000 rows | `max_events` windowed pruning (by design) | Raise `OBSERVABILITY_MAX_EVENTS`, or use `gcp` for durable retention |
