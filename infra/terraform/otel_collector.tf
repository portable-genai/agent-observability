# otel_collector.tf — The OpenTelemetry Collector for catalog system Hrz5 (us-central1).
#
# Trace ingest is INFRA, not part of the Hrz5 HTTP contract (SPEC §6): agents export OTLP
# spans here and the collector batches + forwards them to Cloud Trace. Before this file
# the collector was a checked-in config with no provisioned target and no canonical URL
# (see catalog/catalog/plans/plan-hrz5-otlp-collector.md). This provisions it as
# an internal-only Cloud Run service whose config is the checked-in
# infra/otel/otel-collector-config.yaml, mounted from Secret Manager.

# Dedicated runtime SA, least privilege for the three OpenTelemetry signals.
resource "google_service_account" "otel_collector" {
  project      = var.project_id
  account_id   = "hrz-otel-collector"
  display_name = "Hrz5 OpenTelemetry Collector runtime SA"
}

resource "google_project_iam_member" "otel_trace_agent" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.otel_collector.email}"
}

resource "google_project_iam_member" "otel_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.otel_collector.email}"
}

resource "google_project_iam_member" "otel_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.otel_collector.email}"
}

# The collector config travels as a Secret Manager secret (from the checked-in file) so it
# is versioned and mountable without baking it into the image.
resource "google_secret_manager_secret" "otel_config" {
  project   = var.project_id
  secret_id = "hrz-otel-collector-config"

  replication {
    user_managed {
      replicas {
        location = var.region # us-central1 (P-03) — no multi-region replication
      }
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "otel_config" {
  secret      = google_secret_manager_secret.otel_config.id
  secret_data = file("${path.module}/../otel/otel-collector-config.yaml")
}

resource "google_secret_manager_secret_iam_member" "otel_config_access" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.otel_config.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.otel_collector.email}"
}

resource "google_cloud_run_v2_service" "otel_collector" {
  deletion_protection = var.cloud_run_deletion_protection

  project  = var.project_id
  name     = "hrz-otel-collector"
  location = var.region # us-central1 (P-03)

  # Internal-only: the collector is reachable from platform services in the VPC, never
  # the public internet. Invocation is further gated by run.invoker IAM below.
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.otel_collector.email

    # Same bank-held key as the audit service (P-09, practice D5).
    encryption_key = google_kms_crypto_key.audit.id

    containers {
      image = var.otel_collector_image
      args  = ["--config=/etc/otelcol-contrib/config.yaml"]

      # OTLP/HTTP receiver — the endpoint consumers set as OTEL_EXPORTER_OTLP_ENDPOINT.
      ports {
        container_port = 4318
      }

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }

      env {
        name  = "GCP_REGION"
        value = var.region
      }

      volume_mounts {
        name       = "otel-config"
        mount_path = "/etc/otelcol-contrib"
      }
    }

    volumes {
      name = "otel-config"
      secret {
        secret = google_secret_manager_secret.otel_config.secret_id
        items {
          version = "latest"
          path    = "config.yaml"
        }
      }
    }
  }

  depends_on = [
    google_project_service.required,
    google_secret_manager_secret_version.otel_config,
  ]
}

# Only the named caller service accounts may invoke the collector (defence in depth atop
# internal ingress). Compose with plan-hrz-s2s-auth for the HTTP API surface.
resource "google_cloud_run_v2_service_iam_member" "otel_invokers" {
  for_each = toset(var.otel_caller_service_accounts)

  project  = var.project_id
  location = google_cloud_run_v2_service.otel_collector.location
  name     = google_cloud_run_v2_service.otel_collector.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${each.value}"
}

output "otlp_endpoint" {
  description = "Canonical OTLP/HTTP endpoint consumers set as OTEL_EXPORTER_OTLP_ENDPOINT."
  value       = google_cloud_run_v2_service.otel_collector.uri
}
