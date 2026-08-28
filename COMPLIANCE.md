# Compliance map: Hrz5 Agent Observability, Audit & FinOps

How Hrz5 maps to the platform's general principles (P-01..P-12) and rules (R1..R6). Hrz5 is a
narrow system of record, so several principles are owned upstream (Hrz1 redaction) or are
not applicable; those are marked honestly rather than padded.

## Rules

| Rule | Requirement | Hrz5 control |
|---|---|---|
| **R1** | Redaction at the boundary | Enforced upstream by Hrz1 `agent-guardrail-gateway`. Hrz5 only ever receives `redacted_prompt` / `redacted_response`; its store has no raw-PII column, and the `redaction_preserved` eval check proves only redacted text is persisted. |
| **R2** | Immutable (WORM) audit | The audit store is Write-Once-Read-Many. `gcp`: a *locked* Cloud Logging bucket, retention 2557 days (~7y), `locked=true`, encrypted with the bank's own CMEK. `local`: an append-only, hash-chained SQLite stand-in. Append-only is enforced by SQLite triggers, every record is chained (`entry_hash = SHA-256(prev_hash || "\n" || event_json)`), the head and the retention-prune watermark are anchored in an external file, and `agent-observability audit verify | export | restore` proves it. `src/observability/adapters/local/audit.py` states exactly which tamper classes are and are not detected. `onprem`: a placeholder that raises rather than dropping a record. Callers of the ingest are themselves authenticated (`require_service_caller`, SPEC §6.1): `gcp` a Google-signed OIDC ID token (audience + caller allowlist), `local` a constant-time shared secret; `/healthz` stays open. So only enrolled platform services can write to or read the trail, hardening the separation that stops a caller tampering with its own audit record. |
| **R3** | Agent registration / discovery | n/a for Hrz5 (owned by Hrz3 `agent-registry`). |
| **R4** | Eval / model-risk gate | Hrz4-style offline gate (`eval/run_eval.py`) checks audit-trail integrity (parity, provenance, redaction, ordering) on every change. |
| **R5** | Maker-checker on consequential output | n/a: Hrz5 produces no agent output; it records the maker-checker `decision` (`escalated`) emitted upstream. |
| **R6** | Data residency | Every managed resource uses the allowlisted deployment region; default `asia-southeast1`. The allowlist is enforced three times: `terraform plan` validates `var.region` against `var.allowed_regions`, the `gcp.resourceLocations` Org Policy (`infra/terraform/org_policy.tf`) refuses out-of-region creates that bypass Terraform, and the app itself fails closed at load (`observability.config.ResidencyError`). |

## General principles

| Principle | Hrz5 control |
|---|---|
| **P-01** human-in-the-loop | n/a directly: Hrz5 stores the upstream `decision` (`allowed` / `blocked` / `escalated`) so a reviewer can audit maker-checker outcomes. |
| **P-02** no lock-in / reversibility | Ports & adapters. The `local` profile runs the whole domain **off-cloud** (SDK-free SQLite WORM stand-in, proven by the end-to-end CLI smoke and the contract test); the `onprem` profile is the documented Google Distributed Cloud exit (fail-fast placeholder satisfying the same Protocol). One env var (`OBSERVABILITY_PROFILE`) switches the backend. |
| **P-03** data residency | All managed resources use the selected region; the local store is on the operator's own disk. `allowed_regions` is the one list Terraform, Org Policy and the app all validate against, so a second approved region is a tfvars / env change and an unapproved one fails closed. `OBSERVABILITY_ALLOWED_REGIONS` is read in three states, so an allowlist an operator set to an empty value refuses at load instead of inheriting the shipped list. |
| **P-04** no raw PII in logs | Only `redacted_*` fields are stored; redaction happens upstream (R1). |
| **P-05** least privilege | The `gcp` service account writes only the audit log and reads only the locked bucket (see the dedicated runtime service account and role grants in `infra/terraform/cloud_run.tf`). The `/v1/audit` ingest also authenticates the calling service (OIDC ID token verified against an audience + caller allowlist on `gcp`; a shared secret on a deliberately chosen `local`), so only named callers reach the WORM store. Absence is never consent: with no profile chosen, no service token, or a token or allowlist set to an empty value, the ingest refuses with `503` rather than admitting the caller (`tests/test_profile_single_source.py`, `tests/test_s2s_auth.py`). |
| **P-06** maker-checker | Hrz5 records the upstream maker-checker `decision`; it does not itself gate. |
| **P-07** explainability / citations | `AuditEvent.citations` carry regulator-grade, page-level provenance, stored verbatim and read back unchanged (the `citation_provenance` eval check). |
| **P-08** immutable audit + read auditing | The locked bucket plus a `DATA_READ` audit config means every *read* of the audit store is itself audited; the offline gate guards the integrity invariants; and the offline / on-premises stand-in is hash-chained and externally anchored, so an edit, an interior deletion or a truncated tail is detectable rather than merely improbable (`tests/test_audit_chain.py`). |
| **P-09** encryption | `gcp`: a bank-held CMEK in the deployment region (`infra/terraform/cmek.tf`), bound explicitly per service to the locked log bucket, the BigQuery FinOps dataset and both Cloud Run services, with rotation as a variable (`key_rotation_period`). The `gcp.restrictNonCmekServices` Org Policy stops a service being created without it. Destroying the key crypto-shreds the trail, which is the only lever left once `locked = true` forbids deletion. |
| **P-10** supply-chain integrity | Core install is framework-light; google-cloud SDKs live in the `[gcp]` extra and import lazily, so the default `local` path pulls no google-cloud package. |
| **P-11** observability | Hrz5 *is* the platform's observability system: tracing (OTel collector), audit (this service), FinOps (BigQuery export). |
| **P-12** documented exit path | `onprem` placeholders raise `NotImplementedError` with a migration message; the CLI exits `2`. Combined with `local` proving the domain runs off-cloud, the exit is concrete, not theoretical. |

## Proof artifacts

* `pytest -m 'not integration' -q`: unit + contract tests pass offline (local profile).
* `tests/test_adapter_parity.py`: both `local` (working WORM) and `onprem` (fail-fast)
  satisfy `AuditSinkPort`.
* `python eval/run_eval.py`: audit-integrity gate passes (exit 0).
* `agent-observability seed && agent-observability read`: a real, page-cited audit
  artifact end to end under `local`, with no Google Cloud SDK and no emulators.
* `OBSERVABILITY_PROFILE=onprem agent-observability read`: exits `2` with the migration
  message.
* `agent-observability audit verify`: re-derives the hash chain over the local trail;
  `tests/test_audit_chain.py` doctors, deletes, truncates, fabricates unchained rows and
  forges retention prunes and asserts each is caught, asserts that the following append
  cannot launder any of them, and asserts the classes that are honestly NOT caught without
  an anchor).
* `terraform -chdir=infra/terraform validate`: the residency, CMEK and dry-run VPC-SC
  posture is valid Terraform with no cloud credentials.

## Per-regulator crosswalk (adopter-owned)

**Ownership: the adopting institution owns this section, not upstream Hrz5.** The rows below
are a filled-in TEMPLATE for one home regulator (MAS) so the shape is unambiguous. Upstream
will not keep any regulator's clause numbering current: a regulator reference is a legal
interpretation your compliance function makes, and merging an upstream change must never
silently alter it. Copy the table, keep it in your fork, and add your own regulators
(HKMA SA-2, RBI, PRA SS2/21, EU AI Act, and so on) as further tables.

| MAS reference | Obligation (adopter's own reading) | Hrz5 evidence |
|---|---|---|
| MAS 626 / TRM Guidelines 11 | Audit trail of system activity, retained and protected from modification | Locked Cloud Logging bucket, 2557-day retention, `locked = true` (`infra/terraform/logging_worm.tf`); hash-chained offline stand-in with `audit verify` |
| MAS TRM Guidelines 8 | Access control and segregation of duties over the audit record | S2S OIDC / shared-secret caller authentication (`src/observability/api/security.py`), writer and approver service accounts validated disjoint (`infra/terraform/variables.tf`) |
| MAS TRM Guidelines 13 | Cryptographic key management for protected data | Bank-held CMEK per service with a declared rotation period (`infra/terraform/cmek.tf`) |
| MAS Outsourcing Guidelines 5.6 | Ability to exit the service provider | `onprem` profile plus `audit export` / `audit restore` in open JSON Lines (`scripts/portability_demo.py`) |
| MAS 626 (record retention) | Retention period appropriate to the record class | `retention_days` variable, defaulted to ~7 years and adopter-set before the irreversible lock |

**Adopter checklist for this appendix:** confirm the clause numbers against the current
instrument, replace the reading in the middle column with your compliance function's own,
add the regulators you are actually supervised by, and record who signed it off and when.
