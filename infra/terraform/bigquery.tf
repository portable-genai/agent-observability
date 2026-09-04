# bigquery.tf — FinOps: BigQuery dataset + a log sink that mirrors the audit stream into
# it for token cost / latency dashboards.
#
# The LOCKED log bucket (logging_worm.tf) remains the WORM system of record (rule R2).
# This BigQuery copy is purely ANALYTICAL — safe to query, join, and aggregate without
# touching the immutable trail. See the FinOps note in README.md for example SQL.

resource "google_bigquery_dataset" "finops" {
  project = var.project_id
  # dataset_id matches settings.yaml finops.bigquery_dataset
  dataset_id    = "agent_finops"
  friendly_name = "Agent platform FinOps"
  description   = "Analytical mirror of agent-observability events: token cost + latency dashboards."
  location      = var.region # us-central1 (P-03 residency)

  # Roll off raw analytical rows after ~1 year; the WORM bucket keeps the 7y record.
  default_table_expiration_ms = 1000 * 60 * 60 * 24 * 365

  # Bank-held key, not Google-managed default encryption (P-09, practice D5).
  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.audit.id
  }

  # EXPLICIT access, because BigQuery's implicit default is not least privilege: a dataset
  # created without an access block is given projectOwners/projectEditors/projectViewers
  # special groups, which hands every project editor read-write on the analytical mirror of
  # the audit stream.
  #
  # It is also unshippable under a domain-restricted org. Those implicit grants expand to
  # principals the allowedPolicyMemberDomains policy has not permitted, and dataset creation
  # fails with "One or more users named in the policy do not belong to a permitted customer"
  # — which is how this surfaced, on the first real apply into a policy-constrained project
  # (2026-08-24). Naming the identities makes the dataset both least-privilege and
  # deployable, rather than widening the domain policy to accommodate a default nobody chose.
  access {
    role          = "OWNER"
    user_by_email = google_service_account.run.email
  }

  dynamic "access" {
    for_each = toset(var.release_approver_service_accounts)
    content {
      role          = "READER"
      user_by_email = access.value
    }
  }

  depends_on = [
    google_project_service.required,
    google_kms_crypto_key_iam_member.service_agents,
  ]
}

# Mirror the audit log into BigQuery (token usage lives in jsonPayload.metadata).
resource "google_logging_project_sink" "audit_to_bigquery" {
  project     = var.project_id
  name        = "agent-observability-to-bigquery"
  description = "Mirrors agent-observability-audit into BigQuery for FinOps (analytical only)."

  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.finops.dataset_id}"

  filter = "logName=\"projects/${var.project_id}/logs/${local.audit_log_name}\""

  unique_writer_identity = true

  bigquery_options {
    use_partitioned_tables = true
  }
}

# Let the BigQuery sink's writer identity write into the dataset.
resource "google_bigquery_dataset_iam_member" "sink_writer" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.finops.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.audit_to_bigquery.writer_identity
}
