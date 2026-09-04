# apis.tf — Enable the Google Cloud APIs agent-observability needs. Pinned project, no global defaults.

resource "google_project_service" "required" {
  for_each = toset([
    "logging.googleapis.com",          # WORM audit bucket + sinks (rule R2)
    "cloudtrace.googleapis.com",       # OpenTelemetry trace backend
    "monitoring.googleapis.com",       # metrics, dashboards, SLOs, and alerts
    "bigquery.googleapis.com",         # FinOps export (token cost / latency)
    "run.googleapis.com",              # Cloud Run service
    "artifactregistry.googleapis.com", # container image registry
    "secretmanager.googleapis.com",    # OTLP collector config (mounted secret)
    "firestore.googleapis.com",        # transactional audit idempotency ledger
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}
