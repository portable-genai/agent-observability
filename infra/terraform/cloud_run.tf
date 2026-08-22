# cloud_run.tf — The Hrz5 observability service on Cloud Run (us-central1).
#
# Runs the 'gcp' profile so audit writes hit the locked Cloud Logging bucket. Ingress is
# internal: only other platform services (e.g. Rsk1) inside the VPC / project call it.

# Dedicated runtime service account, least privilege.
resource "google_service_account" "run" {
  project      = var.project_id
  account_id   = "agent-observability"
  display_name = "Hrz5 Agent Observability runtime SA"
}

# Write audit events to Cloud Logging (routed to the locked WORM bucket by the sink).
resource "google_project_iam_member" "run_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.run.email}"
}

# Read recent events back for demos (GET /v1/audit).
resource "google_project_iam_member" "run_log_viewer" {
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.run.email}"
}

# Export reasoning-trace spans to Cloud Trace.
resource "google_project_iam_member" "run_trace_agent" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.run.email}"
}

resource "google_cloud_run_v2_service" "observability" {
  project  = var.project_id
  name     = "agent-observability"
  location = var.region # us-central1 (P-03)

  # Internal-only: the audit sink is not a public endpoint.
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.run.email

    # Bank-held key over the revision's boot disk and in-transit-to-disk state (P-09).
    encryption_key = google_kms_crypto_key.audit.id

    containers {
      image = var.container_image

      ports {
        container_port = 8085
      }

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "GCP_REGION"
        value = var.region
      }
      env {
        name  = "OBSERVABILITY_PROFILE"
        value = "gcp"
      }
      env {
        name  = "OBSERVABILITY_S2S_AUDIENCE"
        value = var.service_audience
      }
      env {
        name  = "OBSERVABILITY_S2S_ALLOWED_CALLERS"
        value = join(",", var.audit_writer_service_accounts)
      }
      env {
        name  = "OBSERVABILITY_RELEASE_APPROVERS"
        value = join(",", var.release_approver_service_accounts)
      }
      env {
        name  = "OBSERVABILITY_WORM_BUCKET"
        value = google_logging_project_bucket_config.worm_audit.bucket_id
      }
      env {
        name  = "OBSERVABILITY_LOG_NAME"
        value = local.audit_log_name
      }
      env {
        name  = "OBSERVABILITY_RETENTION_DAYS"
        value = tostring(var.retention_days)
      }
      env {
        name  = "OBSERVABILITY_BQ_DATASET"
        value = google_bigquery_dataset.finops.dataset_id
      }
    }
  }

  depends_on = [
    google_project_service.required,
    google_kms_crypto_key_iam_member.service_agents,
    google_project_iam_member.run_log_writer,
    google_project_iam_member.run_datastore_user,
    google_firestore_database.audit_idempotency,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "audit_writers" {
  for_each = toset(var.audit_writer_service_accounts)
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.observability.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${each.value}"
}

resource "google_cloud_run_v2_service_iam_member" "release_approvers" {
  for_each = toset(var.release_approver_service_accounts)
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.observability.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${each.value}"
}

output "service_uri" {
  description = "Internal URL other platform services (Rsk1) set as HRZ_OBSERVABILITY_URL."
  value       = google_cloud_run_v2_service.observability.uri
}

output "worm_bucket_id" {
  description = "Locked WORM audit bucket id (rule R2)."
  value       = google_logging_project_bucket_config.worm_audit.bucket_id
}

output "finops_dataset" {
  description = "BigQuery FinOps dataset for token cost / latency dashboards."
  value       = google_bigquery_dataset.finops.dataset_id
}
