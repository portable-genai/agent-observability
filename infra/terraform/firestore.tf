# Transactional idempotency ledger for immutable audit ingestion.
#
# Cloud Logging insert IDs deduplicate retries, while this regional Firestore database
# atomically binds each Idempotency-Key to one event ID and payload digest so conflicting
# reuse is rejected across Cloud Run replicas.

resource "google_firestore_database" "audit_idempotency" {
  project     = var.project_id
  name        = "hrz-observability-idempotency"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"

  delete_protection_state = "DELETE_PROTECTION_ENABLED"
  deletion_policy         = "DELETE"

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "run_datastore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.run.email}"
}
